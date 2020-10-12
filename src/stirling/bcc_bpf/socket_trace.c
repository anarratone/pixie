// LINT_C_FILE: Do not remove this line. It ensures cpplint treats this as a C file.

#include <linux/errno.h>
#include <linux/in6.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>

#include "src/stirling/bcc_bpf/protocol_inference.h"
#include "src/stirling/bcc_bpf/utils.h"
#include "src/stirling/bcc_bpf_interface/socket_trace.h"

// TODO(yzhao): Investigate the performance overhead of active_*_info_map.delete(id), when id is not
// in the map. If it's significant, change to only call delete() after knowing that id is in the
// map.

// This keeps instruction count below BPF's limit of 4096 per probe.
// TODO(yzhao): Investigate using tail call to reuse stack space to support loop.
// TODO(PL-914): 4.13 and older kernel versions need smaller number, 10 is tested to work.
// See the referenced Jira issue for more details.
#define LOOP_LIMIT 45

// Determines what percentage of events must be inferred as a certain type for us to consider the
// connection to be of that type. Encoded as a numerator/denominator. Currently set to 20%. While
// this may seem low, one must consider that not all captures are packet-aligned, and the inference
// logic doesn't work on the middle of packets. Moreover, a large data packet would get split up
// and cause issues. This threshold only needs to be larger than the false positive rate, which
// for MySQL is 32/256 based on command only.
const int kTrafficInferenceThresholdNum = 1;
const int kTrafficInferenceThresholdDen = 5;

// This bias is added to the numerator of the traffic inference threshold.
// By using a positive number, it biases messages to be classified as matches,
// when the number of samples is low.
const int kTrafficInferenceBias = 5;

// This is the perf buffer for BPF program to export data from kernel to user space.
BPF_PERF_OUTPUT(socket_data_events);
BPF_PERF_OUTPUT(socket_control_events);

/***********************************************************
 * Internal structs and definitions
 ***********************************************************/

struct connect_args_t {
  const struct sockaddr* addr;
  uint32_t fd;
};

struct accept_args_t {
  struct sockaddr* addr;
};

struct data_args_t {
  uint32_t fd;
  // For send()/recv()/write()/read().
  const char* buf;
  // For sendmsg()/recvmsg()/writev()/readv().
  const struct iovec* iov;
  size_t iovlen;
};

struct close_args_t {
  uint32_t fd;
};

// This control_map is a bit-mask that controls which endpoints are traced in a connection.
// The bits are defined in EndpointRole enum, kRoleClient or kRoleServer. kRoleNone is not
// really used, but is defined for completeness.
// There is a control map element for each protocol.
BPF_PERCPU_ARRAY(control_map, uint64_t, kNumProtocols);

// Map from user-space file descriptors to the connections obtained from accept() syscall.
// Tracks connection from accept() -> close().
// Key is {tgid, fd}.
BPF_HASH(conn_info_map, uint64_t, struct conn_info_t);

// Map from user-space file descriptors to open files obtained from open() syscall.
// Used to filter out file read/writes.
// Tracks connection from open() -> close().
// Key is {tgid, fd}.
BPF_HASH(open_file_map, uint64_t, bool);

// Map from thread to its ongoing accept() syscall's input argument.
// Tracks accept() call from entry -> exit.
// Key is {tgid, pid}.
BPF_HASH(active_accept_args_map, uint64_t, struct accept_args_t);

// Map from thread to its ongoing connect() syscall's input argument.
// Tracks connect() call from entry -> exit.
// Key is {tgid, pid}.
BPF_HASH(active_connect_args_map, uint64_t, struct connect_args_t);

// Map from thread to its ongoing write() syscall's input argument.
// Tracks write() call from entry -> exit.
// Key is {tgid, pid}.
BPF_HASH(active_write_args_map, uint64_t, struct data_args_t);

// Map from thread to its ongoing read() syscall's input argument.
// Tracks read() call from entry -> exit.
// Key is {tgid, pid}.
BPF_HASH(active_read_args_map, uint64_t, struct data_args_t);

// Map from thread to its ongoing close() syscall's input argument.
// Tracks close() call from entry -> exit.
// Key is {tgid, pid}.
BPF_HASH(active_close_args_map, uint64_t, struct close_args_t);

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
BPF_PERCPU_ARRAY(data_buffer_heap, struct socket_data_event_t, 1);

// This array records singular values that are used by probes. We group them together to reduce the
// number of arrays with only 1 element.
BPF_PERCPU_ARRAY(control_values, int64_t, kNumControlValues);

/***********************************************************
 * General helper functions
 ***********************************************************/

static __inline uint64_t gen_tgid_fd(uint32_t tgid, int fd) {
  return ((uint64_t)tgid << 32) | (uint32_t)fd;
}

static __inline void set_open_file(uint64_t id, int fd) {
  uint32_t tgid = id >> 32;
  uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
  bool kTrue = 1;
  open_file_map.insert(&tgid_fd, &kTrue);
}

static __inline bool is_open_file(uint64_t id, int fd) {
  uint32_t tgid = id >> 32;
  uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
  bool* open_file = open_file_map.lookup(&tgid_fd);
  return (open_file != NULL);
}

static __inline void clear_open_file(uint64_t id, int fd) {
  uint32_t tgid = id >> 32;
  uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
  open_file_map.delete(&tgid_fd);
}

// The caller must memset conn_info to '0', otherwise the behavior is undefined.
static __inline void init_conn_info(uint32_t tgid, uint32_t fd, struct conn_info_t* conn_info) {
  conn_info->conn_id.upid.tgid = tgid;
  conn_info->conn_id.upid.start_time_ticks = get_tgid_start_time();
  conn_info->conn_id.fd = fd;
  conn_info->conn_id.tsid = bpf_ktime_get_ns();
}

static __inline struct conn_info_t* get_conn_info(uint32_t tgid, uint32_t fd) {
  uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
  struct conn_info_t new_conn_info = {};
  new_conn_info.addr_valid = false;
  struct conn_info_t* conn_info = conn_info_map.lookup_or_init(&tgid_fd, &new_conn_info);
  // Use TGID zero to detect that a new conn_info needs to be initialized.
  if (conn_info->conn_id.upid.tgid == 0) {
    init_conn_info(tgid, fd, conn_info);
  }
  return conn_info;
}

/***********************************************************
 * Trace filtering functions
 ***********************************************************/

static __inline bool should_trace_classified(const struct traffic_class_t* traffic_class) {
  uint32_t protocol = traffic_class->protocol;
  uint64_t kZero = 0;
  // TODO(yzhao): BCC doc states BPF_PERCPU_ARRAY: all array elements are **pre-allocated with zero
  // values** (https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md). That suggests
  // lookup() suffices. But this seems more robust, as BCC behavior is often not intuitive.
  uint64_t control = *control_map.lookup_or_init(&protocol, &kZero);
  return control & traffic_class->role;
}

// Returns true if detection passes threshold. Right now this only makes sense for MySQL.
//
// TODO(yzhao): Remove protocol detection threshold.
static __inline bool protocol_detection_passes_threshold(const struct conn_info_t* conn_info) {
  if (conn_info->traffic_class.protocol == kProtocolPGSQL) {
    // Since some protocols are hard to infer from a single event, we track the inference stats over
    // time, and then use the match rate to determine whether we really want to consider it to be of
    // the protocol or not. This helps reduce polluting events to user-space.
    bool meets_threshold =
        kTrafficInferenceThresholdDen * (conn_info->protocol_match_count + kTrafficInferenceBias) >
        kTrafficInferenceThresholdNum * conn_info->protocol_total_count;
    return meets_threshold;
  }
  return true;
}

static __inline bool is_inet_family(sa_family_t sa_family) {
  return sa_family == AF_INET || sa_family == AF_INET6;
}

// Returns true if the input conn_info should be traced.
// The protocol of the input conn_info must be kProtocolUnknown.
//
// TODO(oazizi/yzhao): Remove this after we implement connections of interests through tgid + fd.
// NOTE: This check is covered by control_map below too, but keeping it around for explicitness.
//
// TODO(yzhao): A connection can have the initial events unclassified, but later being classified
// into a known protocol. Investigate its impact.
static __inline bool should_trace_unclassified(const struct conn_info_t* conn_info) {
  // ALLOW_UNKNOWN_PROTOCOL must be a macro (with bool value) defined when initializing BPF program.
  return ALLOW_UNKNOWN_PROTOCOL && conn_info->addr_valid &&
         is_inet_family(conn_info->addr.sin6_family);
}

static __inline bool should_trace_conn(const struct conn_info_t* conn_info) {
  if (conn_info->traffic_class.protocol == kProtocolUnknown) {
    return should_trace_unclassified(conn_info);
  }
  return protocol_detection_passes_threshold(conn_info) &&
         should_trace_classified(&conn_info->traffic_class);
}

static __inline bool is_stirling_tgid(const uint32_t tgid) {
  int idx = kStirlingTGIDIndex;
  int64_t* target_tgid = control_values.lookup(&idx);
  if (target_tgid == NULL) {
    return false;
  }
  return *target_tgid == tgid;
}

static __inline bool should_trace_tgid(const uint32_t tgid) {
  int idx = kTargetTGIDIndex;
  int64_t* target_tgid = control_values.lookup(&idx);
  if (target_tgid == NULL) {
    return true;
  }
  if (*target_tgid < 0) {
    return true;
  }
  return *target_tgid == tgid;
}

static __inline struct socket_data_event_t* fill_event(enum TrafficDirection direction,
                                                       const struct conn_info_t* conn_info) {
  uint32_t kZero = 0;
  struct socket_data_event_t* event = data_buffer_heap.lookup(&kZero);
  if (event == NULL) {
    return NULL;
  }
  event->attr.timestamp_ns = bpf_ktime_get_ns();
  event->attr.ssl = conn_info->ssl;
  event->attr.direction = direction;
  event->attr.conn_id = conn_info->conn_id;
  event->attr.traffic_class = conn_info->traffic_class;
  return event;
}

// TODO(oazizi): This function should go away once the protocol is identified externally.
//               Also, could move this function into the header file, so we can test it.
static __inline void update_traffic_class(struct conn_info_t* conn_info,
                                          enum TrafficDirection direction, const char* buf,
                                          size_t count) {
  // TODO(oazizi): Future architecture should have user-land provide the traffic_class.
  // TODO(oazizi): conn_info currently works only if tracing on the send or recv side of a process,
  //               but not both simultaneously, because we need to mark two traffic classes.

  if (conn_info == NULL) {
    return;
  }
  conn_info->protocol_total_count += 1;

  // Try to infer connection type (protocol) based on data.
  struct traffic_class_t traffic_class = infer_traffic(direction, buf, count);

  // Could not infer the traffic.
  if (traffic_class.protocol == kProtocolUnknown) {
    return;
  }

  if (conn_info->traffic_class.protocol == kProtocolUnknown) {
    // TODO(oazizi): Look for only certain protocols on write/send()?
    conn_info->traffic_class = traffic_class;
    conn_info->protocol_match_count = 1;
  } else if (conn_info->traffic_class.protocol == traffic_class.protocol) {
    conn_info->protocol_match_count += 1;
  }
}

/***********************************************************
 * Perf submit functions
 ***********************************************************/

static __inline bool should_trace_sockaddr_family(sa_family_t sa_family) {
  return sa_family == AF_UNSPEC || sa_family == AF_UNIX || is_inet_family(sa_family);
}

static __inline void submit_new_conn(struct pt_regs* ctx, uint32_t tgid, uint32_t fd,
                                     const struct sockaddr* addr) {
  struct conn_info_t conn_info = {};
  conn_info.addr_valid = true;
  conn_info.addr = *((struct sockaddr_in6*)addr);
  init_conn_info(tgid, fd, &conn_info);

  uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
  conn_info_map.update(&tgid_fd, &conn_info);

  // While we keep all sa_family types in conn_info_map,
  // we only send connections with supported protocols to user-space.
  // We use the same filter function to avoid sending data of unwanted connections as well.
  if (!should_trace_sockaddr_family(addr->sa_family)) {
    return;
  }

  struct socket_control_event_t conn_event = {};
  conn_event.type = kConnOpen;
  conn_event.open.timestamp_ns = bpf_ktime_get_ns();
  conn_event.open.conn_id = conn_info.conn_id;
  conn_event.open.addr = conn_info.addr;

  socket_control_events.perf_submit(ctx, &conn_event, sizeof(struct socket_control_event_t));
}

static __inline void submit_close_event(struct pt_regs* ctx, struct conn_info_t* conn_info) {
  struct socket_control_event_t close_event = {};
  close_event.type = kConnClose;
  close_event.close.timestamp_ns = bpf_ktime_get_ns();
  close_event.close.conn_id = conn_info->conn_id;
  close_event.close.rd_bytes = conn_info->rd_bytes;
  close_event.close.wr_bytes = conn_info->wr_bytes;

  socket_control_events.perf_submit(ctx, &close_event, sizeof(struct socket_control_event_t));
}

// TODO(yzhao): We can write a test for this, by define a dummy bpf_probe_read() function. Similar
// in idea to a mock in normal C++ code.

// Writes the input buf to event, and submits the event to the corresponding perf buffer.
// Returns the bytes output from the input buf. Note that is not the total bytes submitted to the
// perf buffer, which includes additional metadata.
// If send_data is false, only the metadata is sent for accounting purposes (used for connection
// stats).
static __inline void perf_submit_buf(struct pt_regs* ctx, const enum TrafficDirection direction,
                                     const char* buf, size_t buf_size,
                                     struct conn_info_t* conn_info,
                                     struct socket_data_event_t* event, bool send_data) {
  switch (direction) {
    case kEgress:
      event->attr.pos = conn_info->wr_bytes;
      conn_info->wr_bytes += buf_size;
      break;
    case kIngress:
      event->attr.pos = conn_info->rd_bytes;
      conn_info->rd_bytes += buf_size;
      break;
  }

  // Record original size of packet. This may get truncated below before submit.
  event->attr.msg_size = buf_size;

  // This rest of this function has been written carefully to keep the BPF verifier happy in older
  // kernels, so please take care when modifying.
  //
  // Logically, what we'd like is the following:
  //    size_t msg_size = buf_size < sizeof(event->msg) ? buf_size : sizeof(event->msg);
  //    bpf_probe_read(&event->msg, msg_size, buf);
  //    event->attr.msg_size = buf_size;
  //    socket_data_events.perf_submit(ctx, event, size_to_submit);
  //
  // But this does not work in kernel versions 4.14 or older, for various reasons:
  //  1) the verifier does not like a bpf_probe_read with size 0.
  //       - Useful link: https://www.mail-archive.com/netdev@vger.kernel.org/msg199918.html
  //  2) the verifier does not like a perf_submit that is larger than sizeof(event).
  //
  // While it is often obvious to us humans that these are not problems,
  // the older verifiers can't prove it to themselves.
  //
  // We often try to provide hints to the verifier using approaches like
  // 'if (msg_size > 0)' around the code, but it turns out that clang is often smarter
  // than the verifier, and optimizes away the structural hints we try to provide the verifier.
  //
  // Solution below involves using a volatile asm statement to prevent clang from optimizing away
  // certain code, so that code can reach the BPF verifier, and convince it that everything is
  // safe.
  //
  // Tested to work on the following kernels:
  //   4.14.104
  //   4.15.18 (Ubuntu 4.15.0-96-generic)

  if (buf_size > MAX_MSG_SIZE || buf_size == 0) {
    return;
  }

  // Modify buf_size this way, to reduce the number of BPF instructions.
  // Note that kMask is a constant that can be pulled out of the perf_submit_buf() loop,
  // and so this reduces if-statements inside the loop, as long as the compiler is smart enough.
  const uint32_t kMask = send_data ? 0xffffffff : 0;
  buf_size = buf_size & kMask;

  // Clang is too smart for us, and tries to remove some of the obvious hints we are leaving for the
  // BPF verifier. So we add this NOP volatile statement, so clang can't optimize away some of our
  // if-statements below.
  // By telling clang that buf_size is both an input and output to some black box assembly
  // code, clang has to discard any assumptions on what values this variable can take.
  asm volatile("" : "+r"(buf_size) :);

  // This is not possible, but is required for the verifier.
  if (buf_size > MAX_MSG_SIZE) {
    buf_size = 0;
  }

  // Read an extra byte.
  // Required for 4.14 kernels, which reject bpf_probe_read with size of zero.
  // Note that event->msg is followed by event->unused, so the extra byte will not clobber
  // anything in the case that buf_size==MAX_MSG_SIZE.
  bpf_probe_read(&event->msg, buf_size + 1, buf);

  event->attr.msg_buf_size = buf_size;
  socket_data_events.perf_submit(ctx, event, sizeof(event->attr) + buf_size);
}

static __inline void perf_submit_wrapper(struct pt_regs* ctx, const enum TrafficDirection direction,
                                         const char* buf, const size_t buf_size,
                                         struct conn_info_t* conn_info,
                                         struct socket_data_event_t* event, bool send_data) {
  int bytes_remaining = buf_size;
  unsigned int i;

#pragma unroll
  for (i = 0; i < CHUNK_LIMIT; ++i) {
    if (bytes_remaining >= MAX_MSG_SIZE) {
      perf_submit_buf(ctx, direction, buf + i * MAX_MSG_SIZE, MAX_MSG_SIZE, conn_info, event,
                      send_data);
      bytes_remaining = bytes_remaining - MAX_MSG_SIZE;
    } else if (bytes_remaining > 0) {
      perf_submit_buf(ctx, direction, buf + i * MAX_MSG_SIZE, bytes_remaining, conn_info, event,
                      send_data);
      bytes_remaining = 0;
    }
  }

  // If the message is too long, then we can't transmit it all.
  // But we still want to record an accurate number of bytes transmitted on the connection.
  //
  // If bytes_remaining is non-zero here, it will appear as missing data in socket_trace_connector,
  // which is exactly what we want it to believe.
  switch (direction) {
    case kEgress:
      conn_info->wr_bytes += bytes_remaining;
      break;
    case kIngress:
      conn_info->rd_bytes += bytes_remaining;
      break;
  }
}

static __inline void perf_submit_iovecs(struct pt_regs* ctx, const enum TrafficDirection direction,
                                        const struct iovec* iov, const size_t iovlen,
                                        const size_t total_size, struct conn_info_t* conn_info,
                                        struct socket_data_event_t* event, bool send_data) {
  // NOTE: The loop index 'i' used to be int. BPF verifier somehow conclude that msg_size inside
  // perf_submit_buf(), after a series of assignment, and passed into a function call, can be
  // negative.
  //
  // The issue can be fixed by changing the loop index, or msg_size inside
  // perf_submit_buf(), to unsigned int (changing to size_t does not work either).
  //
  // We prefer changing loop index, as it appears to be the source of triggering BPF verifier's
  // confusion.
  //
  // NOTE: The syscalls for scatter buffers, {send,recv}msg()/{write,read}v(), access buffers in
  // array order. That means they read or fill iov[0], then iov[1], and so on. They return the total
  // size of the written or read data. Therefore, when loop through the buffers, both the number of
  // buffers and the total size need to be checked. More details can be found on their man pages.
  unsigned int bytes_remaining = total_size;
#pragma unroll
  for (unsigned int i = 0; i < LOOP_LIMIT && i < iovlen && bytes_remaining > 0; ++i) {
    struct iovec iov_cpy;
    bpf_probe_read(&iov_cpy, sizeof(struct iovec), &iov[i]);

    const size_t iov_size = iov_cpy.iov_len < bytes_remaining ? iov_cpy.iov_len : bytes_remaining;

    // TODO(oazizi/yzhao): Should switch this to go through perf_submit_wrapper.
    perf_submit_buf(ctx, direction, iov_cpy.iov_base, iov_size, conn_info, event, send_data);
    bytes_remaining -= iov_size;
  }

  // If the message is too long, then we can't transmit it all.
  // But we still want to record an accurate number of bytes transmitted on the connection.
  //
  // If bytes_remaining is non-zero here, it will appear as missing data in socket_trace_connector,
  // which is exactly what we want it to believe.
  switch (direction) {
    case kEgress:
      conn_info->wr_bytes += bytes_remaining;
      break;
    case kIngress:
      conn_info->rd_bytes += bytes_remaining;
      break;
  }
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

// TODO(oazizi): For consistency, may want to pull reading the return value out
//               to the outer layer, just like the args.

static __inline void process_syscall_open(struct pt_regs* ctx, uint64_t id) {
  int fd = PT_REGS_RC(ctx);

  if (fd < 0) {
    return;
  }

  set_open_file(id, fd);
}

static __inline void process_syscall_connect(struct pt_regs* ctx, uint64_t id,
                                             const struct connect_args_t* args) {
  uint32_t tgid = id >> 32;
  int ret_val = PT_REGS_RC(ctx);

  if (!should_trace_tgid(tgid)) {
    return;
  }

  if (args->fd < 0) {
    return;
  }

  // We allow EINPROGRESS to go through, which indicates that a NON_BLOCK socket is undergoing
  // handshake.
  //
  // In case connect() eventually fails, any write or read on the fd would fail nonetheless, and we
  // won't see spurious events.
  //
  // In case a separate connect() is called concurrently in another thread, and succeeds
  // immediately, any write or read on the fd would be attributed to the new connection.
  if (ret_val < 0 && ret_val != -EINPROGRESS) {
    return;
  }

  submit_new_conn(ctx, tgid, (uint32_t)args->fd, args->addr);
}

static __inline void process_syscall_accept(struct pt_regs* ctx, uint64_t id,
                                            const struct accept_args_t* args) {
  uint32_t tgid = id >> 32;
  int ret_fd = PT_REGS_RC(ctx);

  if (!should_trace_tgid(tgid)) {
    return;
  }

  if (ret_fd < 0) {
    return;
  }

  submit_new_conn(ctx, tgid, (uint32_t)ret_fd, args->addr);
}

static __inline void process_data(struct pt_regs* ctx, uint64_t id,
                                  const enum TrafficDirection direction,
                                  const struct data_args_t* args, bool ssl) {
  uint32_t tgid = id >> 32;
  ssize_t bytes_count = PT_REGS_RC(ctx);

  if (args->fd < 0) {
    return;
  }

  if (bytes_count <= 0) {
    // This read()/write() call failed, or processed nothing.
    return;
  }

  if (is_open_file(id, args->fd)) {
    return;
  }

  if (!should_trace_tgid(tgid)) {
    return;
  }

  struct conn_info_t* conn_info = get_conn_info(tgid, args->fd);
  if (conn_info == NULL) {
    return;
  }

  // Note: From this point on, if exiting early, and conn_info->addr_valid == 0,
  // then call conn_info_map.delete(&tgid_fd) to avoid a BPF map leak.

  uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);

  // While we keep all sa_family types in conn_info_map,
  // we only send connections with supported protocols to user-space.
  if (!should_trace_sockaddr_family(conn_info->addr.sin6_family)) {
    if (!conn_info->addr_valid) {
      conn_info_map.delete(&tgid_fd);
    }
    return;
  }

  if (conn_info->ssl && !ssl) {
    // This connection is tracking SSL now.
    // Don't report encrypted data.
    // Also, note this is a special case. We don't delete conn_info_map entry,
    // because we are still tracking the connection.
    return;
  }

  // TODO(yzhao): Split the interface such that the singular buf case and multiple bufs in msghdr
  // are handled separately without mixed interface. The plan is to factor out helper functions for
  // lower-level functionalities, and call them separately for each case.
  if (args->buf != NULL) {
    update_traffic_class(conn_info, direction, args->buf, bytes_count);
  } else if (args->iov != NULL && args->iovlen > 0) {
    struct iovec iov_cpy;
    bpf_probe_read(&iov_cpy, sizeof(struct iovec), &args->iov[0]);
    // Ensure we are not reading beyond the available data.
    const size_t buf_size = iov_cpy.iov_len < bytes_count ? iov_cpy.iov_len : bytes_count;
    update_traffic_class(conn_info, direction, iov_cpy.iov_base, buf_size);
  }

  // Filter for request or response based on control flags and protocol type.
  if (!should_trace_conn(conn_info)) {
    if (!conn_info->addr_valid) {
      conn_info_map.delete(&tgid_fd);
    }
    return;
  }

  struct socket_data_event_t* event = fill_event(direction, conn_info);
  if (event == NULL) {
    if (!conn_info->addr_valid) {
      conn_info_map.delete(&tgid_fd);
    }
    return;
  }

  bool send_data =
      event->attr.traffic_class.protocol != kProtocolUnknown && !is_stirling_tgid(tgid);

  // TODO(yzhao): Same TODO for split the interface.
  if (args->buf != NULL) {
    perf_submit_wrapper(ctx, direction, args->buf, bytes_count, conn_info, event, send_data);
  } else if (args->iov != NULL && args->iovlen > 0) {
    // TODO(yzhao): iov[0] is copied twice, once in calling update_traffic_class(), and here.
    // This happens to the write probes as well, but the calls are placed in the entry and return
    // probes respectively. Consider remove one copy.
    perf_submit_iovecs(ctx, direction, args->iov, args->iovlen, bytes_count, conn_info, event,
                       send_data);
  }
  return;
}

static __inline void process_syscall_data(struct pt_regs* ctx, uint64_t id,
                                          const enum TrafficDirection direction,
                                          const struct data_args_t* args) {
  process_data(ctx, id, direction, args, /* ssl */ false);
}

static __inline void process_syscall_close(struct pt_regs* ctx, uint64_t id,
                                           const struct close_args_t* close_args) {
  uint32_t tgid = id >> 32;
  int ret_val = PT_REGS_RC(ctx);

  if (close_args->fd < 0) {
    return;
  }

  clear_open_file(id, close_args->fd);

  if (ret_val < 0) {
    // This close() call failed.
    return;
  }

  if (!should_trace_tgid(tgid)) {
    return;
  }

  uint64_t tgid_fd = gen_tgid_fd(tgid, close_args->fd);
  struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
  if (conn_info == NULL) {
    return;
  }

  // Only submit event to user-space if there was a corresponding open or data event reported.
  // This is to avoid polluting the perf buffer.
  if (conn_info->addr.sin6_family != 0 || conn_info->wr_bytes != 0 || conn_info->rd_bytes != 0) {
    submit_close_event(ctx, conn_info);
  }

  conn_info_map.delete(&tgid_fd);
}

/***********************************************************
 * BPF syscall probe function entry-points
 ***********************************************************/

// The following functions are the tracing function entry points.
// There is an entry probe and a return probe for each syscall.
// Information from both the entry and return probes are required
// before a syscall can be processed.
//
// General structure:
//    Entry probe: responsible for recording arguments.
//    Return probe: responsible for retrieving recorded arguments,
//                  extracting the return value,
//                  and processing the syscall with the combined context.

int syscall__probe_ret_open(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // No arguments were stashed; non-existent entry probe.
  process_syscall_open(ctx, id);

  return 0;
}

int syscall__probe_entry_connect(struct pt_regs* ctx, int sockfd, const struct sockaddr* addr,
                                 size_t addrlen) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct connect_args_t connect_args = {};
  connect_args.fd = sockfd;
  connect_args.addr = addr;
  active_connect_args_map.update(&id, &connect_args);

  return 0;
}

int syscall__probe_ret_connect(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL) {
    process_syscall_connect(ctx, id, connect_args);
  }

  active_connect_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_accept(struct pt_regs* ctx, int sockfd, struct sockaddr* addr,
                                size_t* addrlen) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct accept_args_t accept_args;
  accept_args.addr = addr;
  active_accept_args_map.update(&id, &accept_args);

  return 0;
}

int syscall__probe_ret_accept(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
  if (accept_args != NULL) {
    process_syscall_accept(ctx, id, accept_args);
  }

  active_accept_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_accept4(struct pt_regs* ctx, int sockfd, struct sockaddr* addr,
                                 size_t* addrlen) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct accept_args_t accept_args;
  accept_args.addr = addr;
  active_accept_args_map.update(&id, &accept_args);

  return 0;
}

int syscall__probe_ret_accept4(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
  if (accept_args != NULL) {
    process_syscall_accept(ctx, id, accept_args);
  }

  active_accept_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_write(struct pt_regs* ctx, int fd, char* buf, size_t count) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.buf = buf;
  active_write_args_map.update(&id, &write_args);

  return 0;
}

int syscall__probe_ret_write(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_syscall_data(ctx, id, kEgress, write_args);
  }

  active_write_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_send(struct pt_regs* ctx, int fd, char* buf, size_t count) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.buf = buf;
  active_write_args_map.update(&id, &write_args);

  return 0;
}

int syscall__probe_ret_send(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_syscall_data(ctx, id, kEgress, write_args);
  }

  active_write_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_read(struct pt_regs* ctx, int fd, char* buf, size_t count) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.buf = buf;
  active_read_args_map.update(&id, &read_args);

  return 0;
}

int syscall__probe_ret_read(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_syscall_data(ctx, id, kIngress, read_args);
  }

  active_read_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_recv(struct pt_regs* ctx, int fd, char* buf, size_t count) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.buf = buf;
  active_read_args_map.update(&id, &read_args);

  return 0;
}

int syscall__probe_ret_recv(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_syscall_data(ctx, id, kIngress, read_args);
  }

  active_read_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_sendto(struct pt_regs* ctx, int fd, char* buf, size_t count) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.buf = buf;
  active_write_args_map.update(&id, &write_args);

  return 0;
}

int syscall__probe_ret_sendto(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_syscall_data(ctx, id, kEgress, write_args);
  }

  active_write_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_sendmsg(struct pt_regs* ctx, int fd, const struct user_msghdr* msghdr) {
  uint64_t id = bpf_get_current_pid_tgid();

  if (msghdr != NULL) {
    // Stash arguments.
    struct data_args_t write_args = {};
    write_args.fd = fd;
    write_args.iov = msghdr->msg_iov;
    write_args.iovlen = msghdr->msg_iovlen;
    active_write_args_map.update(&id, &write_args);
  }

  return 0;
}

int syscall__probe_ret_sendmsg(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_syscall_data(ctx, id, kEgress, write_args);
  }

  active_write_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_recvmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msghdr) {
  uint64_t id = bpf_get_current_pid_tgid();

  if (msghdr != NULL) {
    // Stash arguments.
    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.iov = msghdr->msg_iov;
    read_args.iovlen = msghdr->msg_iovlen;
    active_read_args_map.update(&id, &read_args);
  }

  return 0;
}

int syscall__probe_ret_recvmsg(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_syscall_data(ctx, id, kIngress, read_args);
  }

  active_read_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_writev(struct pt_regs* ctx, int fd, const struct iovec* iov, int iovlen) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.iov = iov;
  write_args.iovlen = iovlen;
  active_write_args_map.update(&id, &write_args);

  return 0;
}

int syscall__probe_ret_writev(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_syscall_data(ctx, id, kEgress, write_args);
  }

  active_write_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_readv(struct pt_regs* ctx, int fd, struct iovec* iov, int iovlen) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.iov = iov;
  read_args.iovlen = iovlen;
  active_read_args_map.update(&id, &read_args);

  return 0;
}

int syscall__probe_ret_readv(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_syscall_data(ctx, id, kIngress, read_args);
  }

  active_read_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_close(struct pt_regs* ctx, unsigned int fd) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct close_args_t close_args;
  close_args.fd = fd;
  active_close_args_map.update(&id, &close_args);

  return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  const struct close_args_t* close_args = active_close_args_map.lookup(&id);
  if (close_args != NULL) {
    process_syscall_close(ctx, id, close_args);
  }

  active_close_args_map.delete(&id);
  return 0;
}

// TODO(oazizi): Look into the following opens:
// 1) Why does the syscall table only include sendto, while Linux source code and man page list both
// sendto and send? 2) What do we do when the sendto() is called with a dest_addr provided? I
// believe this overrides the conn_info.

// Includes HTTP2 tracing probes.
#include "src/stirling/bcc_bpf/go_grpc.c"

#include "src/stirling/bcc_bpf/openssl_trace.c"

# Copyright 2018- The Pixie Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load(":repository_locations.bzl", "REPOSITORY_LOCATIONS")

# Make all contents of an external repository accessible under a filegroup.
# Used for external HTTP archives, e.g. cares.
BUILD_ALL_CONTENT = """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])"""

def _repo_impl(name, **kwargs):
    # `existing_rule_keys` contains the names of repositories that have already
    # been defined in the Bazel workspace. By skipping repos with existing keys,
    # users can override dependency versions by using standard Bazel repository
    # rules in their WORKSPACE files.
    existing_rule_keys = native.existing_rules().keys()
    if name in existing_rule_keys:
        # This repository has already been defined, probably because the user
        # wants to override the version. Do nothing.
        return

    location = REPOSITORY_LOCATIONS[name]

    # HTTP tarball at a given URL. Add a BUILD file if requested.
    http_archive(
        name = name,
        urls = location["urls"],
        sha256 = location["sha256"],
        strip_prefix = location.get("strip_prefix", ""),
        **kwargs
    )

# For bazel repos do not require customization.
def _bazel_repo(name, **kwargs):
    _repo_impl(name, **kwargs)

# With a predefined "include all files" BUILD file for a non-Bazel repo.
def _include_all_repo(name, **kwargs):
    kwargs["build_file_content"] = BUILD_ALL_CONTENT
    _repo_impl(name, **kwargs)

def _com_llvm_lib():
    native.new_local_repository(
        name = "com_llvm_lib",
        build_file = "bazel/external/llvm.BUILD",
        path = "/opt/clang-11.1",
    )

    native.new_local_repository(
        name = "com_llvm_lib_libcpp",
        build_file = "bazel/external/llvm.BUILD",
        path = "/opt/clang-11.1-libc++",
    )

def _com_github_threadstacks():
    native.local_repository(
        name = "com_github_threadstacks",
        path = "third_party/threadstacks",
    )

def _cc_deps():
    _bazel_repo("com_google_protobuf", patches = ["//bazel/external:protobuf.patch", "//bazel/external:protobuf_text_format.patch"], patch_args = ["-p1"])
    _bazel_repo("com_google_benchmark")
    _bazel_repo("com_google_googletest")
    _bazel_repo("com_github_gflags_gflags")
    _bazel_repo("com_github_google_glog")
    _bazel_repo("com_google_absl")
    _bazel_repo("com_google_flatbuffers")
    _bazel_repo("org_tensorflow")
    _bazel_repo("com_github_neargye_magic_enum")
    _bazel_repo("rules_python")

    _include_all_repo("com_github_gperftools_gperftools", patch_cmds = ["./autogen.sh"])
    _include_all_repo("com_github_nats_io_natsc", patches = ["//bazel/external:natsc.patch"], patch_args = ["-p1"])
    _include_all_repo("com_github_libuv_libuv", patches = ["//bazel/external:libuv.patch"], patch_args = ["-p1"])
    _include_all_repo("com_github_libarchive_libarchive")

    _repo_impl("com_github_apache_arrow", build_file = "//bazel/external:arrow.BUILD")
    _repo_impl("com_github_ariafallah_csv_parser", build_file = "//bazel/external:csv_parser.BUILD")
    _repo_impl("com_github_arun11299_cpp_jwt", build_file = "//bazel/external:cpp_jwt.BUILD")
    _repo_impl("com_github_cameron314_concurrentqueue", build_file = "//bazel/external:concurrentqueue.BUILD")
    _repo_impl("com_github_cmcqueen_aes_min", patches = ["//bazel/external:aes_min.patch"], patch_args = ["-p1"], build_file = "//bazel/external:aes_min.BUILD")
    _repo_impl("com_github_cyan4973_xxhash", build_file = "//bazel/external:xxhash.BUILD")
    _repo_impl("com_github_nlohmann_json", build_file = "//bazel/external:nlohmann_json.BUILD")
    _repo_impl("com_github_packetzero_dnsparser", build_file = "//bazel/external:dnsparser.BUILD")
    _repo_impl("com_github_rlyeh_sole", build_file = "//bazel/external:sole.BUILD")
    _repo_impl("com_github_serge1_elfio", build_file = "//bazel/external:elfio.BUILD")
    _repo_impl("com_github_tencent_rapidjson", build_file = "//bazel/external:rapidjson.BUILD")
    _com_github_threadstacks()
    _repo_impl("com_google_double_conversion", build_file = "//bazel/external:double_conversion.BUILD")
    _repo_impl(
        "com_github_google_sentencepiece",
        build_file = "//bazel/external:sentencepiece.BUILD",
        patches = ["//bazel/external:sentencepiece.patch"],
        patch_args = ["-p1"],
    )

def _go_deps():
    # Add go specific imports here when necessary.
    pass

def list_pl_deps(name):
    repo_urls = list()
    for repo_name, repo_config in REPOSITORY_LOCATIONS.items():
        urls = repo_config["urls"]
        best_url = None
        for url in urls:
            if url.startswith("https://github.com") or best_url == None:
                best_url = url
        repo_urls.append(best_url)

    native.genrule(
        name = name,
        outs = ["{}.out".format(name)],
        cmd = 'echo "{}" > $@'.format("\n".join(repo_urls)),
        visibility = ["//visibility:public"],
    )

def pl_deps():
    _com_llvm_lib()

    _bazel_repo("io_bazel_rules_go")
    _bazel_repo("com_github_bazelbuild_buildtools")
    _bazel_repo("bazel_skylib")

    _bazel_repo("io_bazel_toolchains")
    _bazel_repo("distroless")
    _bazel_repo("com_google_boringssl")
    _bazel_repo("rules_foreign_cc")
    _bazel_repo("io_bazel_rules_k8s")
    _bazel_repo("io_bazel_rules_closure")

    _repo_impl("io_bazel_rules_docker")
    _repo_impl("bazel_gazelle")
    _repo_impl("com_github_grpc_grpc", patches = ["//bazel/external:grpc.patch"], patch_args = ["-p1"])
    _repo_impl("com_intel_tbb", build_file = "//bazel/external:tbb.BUILD")
    _repo_impl("com_google_farmhash", build_file = "//bazel/external:farmhash.BUILD")
    _repo_impl("com_github_h2o_picohttpparser", build_file = "//bazel/external:picohttpparser.BUILD")

    _cc_deps()
    _go_deps()

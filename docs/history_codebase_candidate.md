# KernelDump 코드 · 기능 · 검증 근거 기준 문서

**핵심 결론:** KernelDump(버전 **1.4.0**)는 커널 모듈을 올리거나 프로세스를 멈추지 않고, 리눅스 `/proc/kpageflags`(물리 페이지 상태 표)와 실행 커널의 BTF(커널 구조체 크기·위치 정보)를 읽어 **커널 메모리와 핵심 실행·통신·파일 캐시 증거만 골라 Sparse LiME(0-구간 디스크 쓰기를 건너뛴 LiME 물리 메모리 이미지)로 저장**하는 단일 실행 도구입니다. `1.4.0`에서는 기존 3단계 명령(`check`·`capture`·`verify`)을 단일 명령으로 합치고, 4 KiB AVX2 기반 Sparse LiME 쓰기와 버퍼 재사용 파이프라인, `--allow-exited-pod` 옵션, `--max-write-mbps` 쓰기 속도 제한을 적용했습니다.

---

## 1. 핵심 용어 쉽게 이해하기

- **PFN (Page Frame Number)**: 물리 RAM을 4 KiB 칸으로 나눌 때 각 칸에 붙는 일련번호입니다.
- **`/proc/kpageflags`**: 각 PFN 칸이 현재 어떤 용도(커널 SLAB 객체, 페이지 테이블, 익명 사용자 메모리, 파일 캐시 등)로 쓰이고 있는지 비트로 알려 주는 커널 읽기 파일입니다.
- **BTF (`/sys/kernel/btf/vmlinux`)**: 지금 실행 중인 리눅스 커널이 직접 들고 있는 구조체 설계도(필드 위치·크기)입니다. 덕분에 커널 버전마다 오프셋을 코드에 직접 적어 둘 필요가 없습니다.
- **LiME 형식**: 각 물리 메모리 구간 앞에 `0x4c694d45` 매직 값과 시작·끝 물리 주소를 담은 32바이트 헤더를 붙여 순서대로 저장하는 물리 메모리 덤프 표준 형식입니다.
- **Sparse LiME(희소 LiME)**: LiME 파일의 논리 주소와 헤더 형식은 그대로 유지하되, 본문 중 4 KiB 칸 전체가 0바이트인 구간은 디스크에 쓰지 않고 파일 위치만 건너뛰어(`seek`) 실제 디스크 사용량과 I/O 부담을 줄이는 저장 방식입니다.

---

## 2. 단일 통합 실행 흐름 (`preflight -> acquire -> verify_fast`)

`kerneldump --output NEW_DIR [옵션]` 한 번만 호출하면 내부에서 3단계가 자동으로 이어집니다.

1. **사전 준비 검사 (`main`, `safe_output`, `source`, `btf`)**:
   - 출력 디렉터리를 심볼릭 링크 차단(`O_NOFOLLOW`)·소유자 전용 권한(`0o700`)으로 검사하고 임시 프로브 파일을 생성·동기화·무교체 게시(`SYS_renameat2(..., RENAME_NOREPLACE)`)·삭제해 저장소가 안전한지 확인합니다(`probe_storage`).
   - 10% of System RAM(최소 1 GiB) 기준 여유 공간을 점검합니다(`check_available_space`).
   - `/sys/kernel/btf/vmlinux` 매직(`0x9feb`, 최대 64 MiB)과 필수 커널 6개 필드·`/proc/kcore`·`/proc/kpageflags`·`/proc/kallsyms`·샘플 PFN 읽기를 검증합니다.
2. **PFN 선별 + 추가 증거 수집 (`source`, `pod_scope`, `code_pages`, `resources`, `resources/cache`)**:
   - `/proc/iomem`에서 시스템 RAM 범위를 읽고(`ram_ranges`), `/proc/kpageflags`의 `KEEP = (1<<7)|(1<<26)`(SLAB·PGTABLE) 플래그와 제외(`EXCLUDE`)·위험(`UNSAFE`) 마스크를 기준으로 커널에 꼭 필요한 PFN을 고릅니다.
   - Volatility/커널 순회 안정성을 위해 SLAB·PGTABLE 주변 이웃 페이지까지 함께 보존합니다(`classify_with_neighbors`).
   - 기본 `kernel-focused` 정책은 여기에 아래 3종류 추가 증거를 **중복 제거 합계 4,096페이지(본문 최대 16 MiB)** 한도 안에서 번갈아(라운드로빈) 더합니다.
     - `--pod <전체_Pod_UID>`를 주면 `/proc/self/ns/{pid,cgroup}`가 호스트 `init_pid_ns`·`init_cgroup_ns`와 일치하는지 먼저 검증한 뒤(불일치 시 노드 전체로 우회하지 않고 종료 코드 `1` 반환), 해당 Pod 소속 프로세스만 추가 탐색합니다.
     - 호스트 네임스페이스 뷰에서 대상 Pod 프로세스가 모두 이미 종료된 경우 `--allow-exited-pod`를 함께 주면 노드 전체 커널 수집을 계속 진행합니다.
3. **4 MiB 재사용 파이프라인 · Sparse LiME 쓰기 · 인라인 검증 (`capture`, `verify`)**:
   - 생산자(`produce`)와 쓰기 파이프라인이 4 MiB 청크와 `recycle_tx`/`recycle_rx` 버퍼 풀(최대 32개)로 동적 메모리 재할당을 줄여 `/proc/kcore`를 읽고 씁니다.
   - `write_sparse_lime_body`가 4 KiB 단위 AVX2 연산(`is_all_zero`)으로 0-페이지를 찾으면 디스크 쓰기를 건너뛰어 `sparse_zero_hole_bytes`를 줄이고, `--max-write-mbps`가 있으면 초당 쓰기 속도를 제한합니다(`max_write_mbps * 1_000_000.0`).
   - `FLUSH_WINDOW = 16 MiB`마다 `sync_file_range_write`와 `advise_dontneed`(`POSIX_FADV_DONTNEED`)를 호출해 운영체제 페이지 캐시에 덤프 데이터가 쌓이지 않게 비우고 `set_len`으로 최종 논리 크기를 맞춥니다.
   - 수집 직후 `verify::verify_fast`가 `ranges.jsonl`, `flags_rle_pages_u64`/`flags_sha256`, LiME 헤더, witness, `manifest.json` 카운터와 페이로드 길이를 즉시 대조해 `verified: true`와 함께 `0`으로 종료합니다.

---

## 3. 모듈별 코드 · 기능 · 근거 표

| 파일 | 역할 | 주요 심볼 · 상수 · 근거 |
|---|---|---|
| `src/main.rs` | 단일 CLI 진입, 사전 점검·수집·검증 연결 | `--output`, `--pod`, `--allow-exited-pod`, `--request-id`, `--max-write-mbps 1..10000` (dev: `--scope`, `--chunk-mib 1..16`, `--queue-depth 1..16`), 기본 `kernel-focused`·`4 MiB`·큐 깊이 `2`, 종료 `0/2/1` |
| `src/source.rs` | `kpageflags` 필터링, RAM 범위, 호스트 네임스페이스 검증 | `ReadCounter`, `KEEP = (1<<7)\|(1<<26)`, `EXCLUDE`, `UNSAFE`, `classify_with_neighbors`, `ram_ranges`, `select_pod_with_policy` (`init_pid_ns`·`init_cgroup_ns` 검증), `/proc/kcore`·`/proc/kpageflags`·`/proc/kallsyms` |
| `src/btf.rs` | 실행 커널 BTF 동적 파싱 | `/sys/kernel/btf/vmlinux` (최대 64 MiB), `0x9feb` 매직, 동적 `Field` 오프셋·비트필드 추출 |
| `src/pod_scope.rs` | Pod UID 검증 및 프로세스 소속·시작 시각 대조 | `uid`, `membership`, `start_ticks`, `Identity::current` 읽기 전후 재검증 |
| `src/code_pages.rs` | private 실행(`x`) 영역의 익명 코드 페이지 선별 | `MAX_PAGES = 4096` (16 MiB 상한), `MAX_SCAN_NS = 2_000_000_000`, `anon_pfn` (`present & !(swapped\|file)`), 파일 기반 COW·JIT/무파일 실행 코드 포함 |
| `src/resources.rs` | 소켓 대기열(수신·송신·TCP 재전송·OOM·UDP `reader_queue`) 탐색 | `QUEUE_BYTES = 64 KiB`, 여러 페이지 조각 및 제한된 `frag_list` 추적, folio 마스크 검사 |
| `src/resources/cache.rs` | 열린/닫힌 `memfd`·삭제 후 열린 파일·COW 비교 캐시 탐색 | `CacheState`: `MAX_JOBS = 128`, `MAX_PAGES = 256`, `MAX_FILE = 64 KiB`, `MAX_NS = 100 ms`, `MAX_BYTES = 4 MiB`, `MAX_PROC_MAPS_BYTES = 512 KiB`, `MAX_REVERSE_VMAS = 64`, `memfd_seed` |
| `src/capture.rs` | 생산자-쓰기 파이프라인, Sparse LiME, 캐시 제어, `manifest.json` 기록 | `produce`, `recycle_tx`/`recycle_rx` (`free_bufs` 32), `write_sparse_lime_body`, `FLUSH_WINDOW = 16 MiB`, `set_len`, `allocated_file_bytes`, `sparse_zero_hole_bytes`, `actual_written_bytes`, `lime_header` (`0x4c694d45`) |
| `src/verify.rs` | 전수 SHA-256 검증(`verify`) 및 수집 직후 고속 검증(`verify_fast`) | `verify` (`full_sha256`), `verify_fast` (`fast_header_ledger`), `ranges.jsonl`·`flags_rle_pages_u64`·`flags_sha256`·LiME 헤더·witness 대조 |
| `src/ledger.rs` | `ranges.jsonl` 범위 기록 상한 관리 | `RECORD_LIMIT = 8 MiB` |
| `src/safe_output.rs` | 저장소 안전 검사, AVX2 0-검사, 캐시 힌트, 무교체 게시 | `probe_storage`, `check_available_space`, `advise_dontneed`, `advise_sequential`, `sync_file_range_write`, `allocated_file_bytes`, AVX2 `is_all_zero`, `SYS_renameat2(..., RENAME_NOREPLACE)` |
| `build.rs` / `src/build_info.rs` | 빌드 시 소스·벤더 해시 및 실행 파일 자기 해시 생성 | 컴파일 시 `source_sha256`·`vendor_tree_sha256` 내장, 실행 시 `/proc/self/exe` SHA-256 기록 |
| `src/tests.rs` 외 테스트 모듈 | 필터·보존·`memfd`·스토리지 회귀 단위 테스트 | `src/tests/retention_regressions.rs`, `src/resources/provenance_tests.rs`, `src/resources/cache/memfd_tests.rs` |

---

## 4. 커버리지 보존과 호환 한계

- **커버리지와 비유출 원칙**: 기본 커널 메타데이터 필터는 `--pod`를 주더라도 노드 전체 범위로 유지됩니다. 추가 탐색(익명 실행 코드·소켓 대기열·상주 캐시)만 `--pod` 대상에 좁혀지며, 탐색 중 참조가 바뀌거나 4,096페이지(16 MiB) 한도에 닿으면 조용히 생략하지 않고 상태를 `partial`로 남기고 누락 원인을 `manifest.json`에 기록합니다.
- **중첩 네임스페이스 및 실행 요구 환경**: `/proc/kcore`, `/proc/kpageflags`, `/sys/kernel/btf/vmlinux` 및 `page_offset_base`·`linux_banner` 읽기 권한이 필수이므로 kcore가 없는 환경은 지원하지 않습니다. WSL2처럼 중첩 PID/cgroup 네임스페이스 안에서는 `--pod`가 즉시 거부되며(`--pod requires host PID and cgroup namespace views`), 실제 `--pod` 수집은 호스트 PID·cgroup 네임스페이스 뷰가 있는 Linux 노드에서 실행해야 합니다.
- **분석 도구와의 관계**: 제외된 물리 페이지 구간은 LiME에서 빠진 범위로 기록되므로, 누락 페이지 예외를 처리하지 않는 일반 Volatility 3 `psscan`에서는 스캔이 중단될 수 있습니다(단 `pslist`·`sockstat`·`lsof` 등 커널 메타데이터 플러그인과 전용 분석기 `rrudrok`은 이 형식을 정상 처리합니다).

---

## 5. 검증 근거

- **WSL2 (`6.18.33.2-microsoft-standard-WSL2`) 노드 전체 수집 A/B (`10c367d` 3단계 대 `v1.4.0` 단일 명령)**:
  - 소요 시간: `8,347.846 ms -> 6,101.231 ms` (`-26.9%`, `status: "complete_for_policy"`, `v140_verification: true`).
  - Sparse LiME 효과: 논리 `file_bytes` `1,066,746,240 B` 중 `289,443,840 B`(~276.0 MiB) 0-페이지 쓰기를 건너뛰어 실제 디스크 할당(`allocated_file_bytes`) `802,004,992 B`, 실제 쓰기(`actual_written_bytes`) `777,302,400 B`를 기록했습니다.
  - 무결성 교차 검증: `manifest.lime_sha256`과 디스크 전체 파일 읽기 SHA-256(`1bd87d23...`)이 일치했고, LiME 헤더 `9,740`건 검사 실패 `0`건, 기준판 `kerneldump verify` 전수 검증도 `rc=0` (`"verified": true`, `coverage_ranges: 22940`)으로 통과했습니다.
  - 중첩 네임스페이스 가드: WSL2 중첩 `pid:[4026532221]`/`cgroup:[4026531835]`에서 `--pod` 호출 시 `rc=1`로 거부해 노드 전체 수집으로 우회하지 않음을 확인했습니다.
- **`rrudrok` 분석 호환**: Linux `6.18.33.2` `btf_isf.py` 출력에서 `2^63` 이상 부호 없는 enum 상수 `13`개를 임시 ISF에서만 `i64`로 정규화해 전달했을 때 `rrudrok analyze --verify-hashes`가 오류·경고 `0`건으로 완료(`33,549` 레코드)됐고, `read-memory`로 물리 주소 `0x1000`(`64 B`)과 가상 주소 `linux_banner`(`"Linux version 6.18.33.2-microsoft-standard-WSL2..."`)를 정상 복원했습니다.
- **오프라인 단위/정적 검사**: `cargo fmt --check`, `cargo clippy --offline --locked --all-targets -- -D warnings`(기본 및 `--features development-options`), `cargo test --offline --locked`(99 passed), `python3 scripts/build_release.py --check-vendor`를 모두 통과했습니다.

# KernelDump 저장소 작업 지침

## 기본 문체 및 단일 기준 문서 유지 규칙

- 사용자용 설명 문서([docs/CODEBASE_GUIDE.md](docs/CODEBASE_GUIDE.md), [README.md](README.md))는 핵심 결론과 구체적 동작부터 쉬운 한국어로 쓰고 비유는 쓰지 않는다. 새 용어는 쉬운 말로 뜻을 먼저 풀어서 설명한다.
- 독자용 문서 본문에 검토 기준일, 조사 과정, 작성자 설명, 작업 시각, 예약 상태 같은 관리 기록을 넣지 않는다. 중요한 조건과 한계는 해당 기능을 설명하는 자리에 한 번만 적는다.
- 코드 구조·기능·검증 근거는 [docs/CODEBASE_GUIDE.md](docs/CODEBASE_GUIDE.md) 한 문서에서 유지관리한다.
- `src/` 모듈, 공개 CLI(`--output` 단일 계약), `manifest.json` 또는 `ranges.jsonl` 스키마, 필터 정책, 검증 계약을 변경할 때는 **같은 작업 안에서 `docs/CODEBASE_GUIDE.md`도 함께 갱신**한다.

## 브랜치 및 변경 범위 제한

- 정식 배포 기준 브랜치인 `main`은 사용자 명시 요청 없이 직접 수정·덮어쓰기·force push 하지 않는다. 새 개선·검증 작업은 별도 작업 브랜치(예: `prod-hardening`)에서 진행한다.
- 사용자 명시 요청 없이 `git push`, GitHub 릴리스 발행, 원격 저장소 공개 작업을 수행하지 않는다.

## 오프라인 검증 게이트 (코드 변경 시 필수)

모든 Rust 코드 변경 뒤에는 오프라인·잠금 모드로 아래 4개 검사를 모두 통과해야 완료로 간주한다.

1. `cargo fmt --check`
2. `cargo clippy --offline --locked --all-targets -- -D warnings`
3. `cargo test --offline --locked`
4. `python3 scripts/build_release.py --check-vendor`

수집 경로를 변경한 경우에는 Sparse LiME의 `manifest.lime_sha256`과 디스크 파일 전체 SHA-256 일치, `memory.lime` 내 LiME 헤더(`0x4c694d45`) 검증, `allocated_file_bytes < file_bytes` 희소 할당 확인, 그리고 `rrudrok analyze --verify-hashes` 호환 검증을 함께 수행하고 임시 덤프는 확인 직후 삭제한다.

## 핵심 설계 및 안전 불변식

- **커널 모듈 없이 PFN 플래그 기반으로 커널만 수집**: `/proc/kcore`, `/proc/kpageflags`, `/proc/iomem`, `/proc/kallsyms`, `/sys/kernel/btf/vmlinux`만 사용해 커널 모듈 적재나 프로세스 정지 없이 물리 메모리를 선별 수집한다. 커널 버전별 구조체 오프셋을 하드코딩하지 않고 실행 중인 커널의 BTF에서 추출한다.
- **단일 통합 실행 계약 (`preflight -> acquire -> verify_fast`)**: `kerneldump --output NEW_DIR` 한 번의 호출로 사전 점검, 수집, 경량 사후 검증을 순서대로 수행한다. 별도 보안 설정을 자동 변경하거나 점검 실패를 무시하고 수집을 진행하지 않는다.
- **노드 전체 조건 기반 추가 증거 보존**: 별도 `--pod` 필터 없이 노드 전체에서 private 실행 매핑(`r-xp`)의 익명/COW 페이지, 소켓 큐(`sk_receive_queue`/`sk_write_queue`/`reader_queue`/`tcp_rtx_queue`/`out_of_order_queue`, 큐별 64KiB), 링크가 끊긴 일반 파일(`i_nlink == 0`, 파일별 최대 16MiB)의 열린 FD 및 커널 VMA 트리(`mm_mt`/`mm_rb`) 직접 탐색 기반 공유 `memfd` VMA, 그리고 COW 비교용 원본 캐시 페이지를 모두 보존하고 일반 링크 파일(`i_nlink != 0`, 일반 `tmpfs` 포함)은 제외한다. 폭주 방어용 안전 상한(512MiB, 5초)에 걸리거나 읽기 오류가 발생하면 `partial`과 `issues`를 기록하고, 비정지 수집 중 대상 프로세스·매핑·참조가 바뀐 경우에는 `ranges.jsonl`(`same_pfn`/`same_fields`)과 `live_drift`(`released_before_read_pages`)에 변경 근거를 함께 남긴다.
- **희소 LiME 논리 무결성과 캐시 제어**: 4 KiB 0-페이지를 AVX2로 판별해 디스크 쓰기만 `seek`로 건너뛰되 LiME 헤더와 논리 오프셋 및 `lime_sha256` 논리 바이트 스트림은 온전하게 유지한다. 쓰기 중 `16 MiB` 창마다 `sync_file_range`와 `POSIX_FADV_DONTNEED`를 호출해 페이지 캐시 점유를 제어하고 `SYS_renameat2(..., RENAME_NOREPLACE)`로 무교체 게시한다.

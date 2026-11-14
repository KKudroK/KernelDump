# KernelDump

**버전 1.4.0**은 기존 3단계 명령(`check`·`capture`·`verify`)을 단일 명령으로 통합하고, 4 KiB AVX2 기반 Sparse LiME 쓰기·버퍼 재사용 파이프라인·`16 MiB` 페이지 캐시 비우기(`POSIX_FADV_DONTNEED`)·`--allow-exited-pod`·`--max-write-mbps` 옵션을 추가했습니다. 코드 구조·기능·검증 근거는 [코드 · 기능 기준 문서](docs/CODEBASE_GUIDE.md) 한 문서에서 관리합니다. 아래의 v9·v4·AWS·Volatility 3 결과는 이전 빌드의 기록입니다.

[English](README.md) · [코드 · 기능 기준](docs/CODEBASE_GUIDE.md) · [배포 조건](docs/deployment.md) · [원본 대비 실측](docs/original_comparison.md)

`kerneldump`는 `/proc/kcore`, `/proc/kpageflags`, `/sys/kernel/btf/vmlinux`로 실행 중인 커널 메모리를 선별 수집합니다. 커널 모듈 설치나 프로세스 정지 없이 Sparse LiME 이미지, 주소·수집 범위 원장(`ranges.jsonl`), `manifest.json`을 한 번에 만들고 즉시 사후 검증까지 끝냅니다.

## 실행 (단일 통합 명령)

Linux x86-64 정적 바이너리 하나로 실행합니다. 수집 시 별도 런타임 라이브러리·외부 ISF·설정 파일이 필요하지 않습니다.

```sh
chmod 755 kerneldump
# 노드 전체 커널 중심 수집 (사전 점검 -> 수집 -> 인라인 검증)
sudo ./kerneldump --output /evidence/new_collection
# 특정 Pod 범위 추가 보존 (+ 대역폭 상한)
sudo ./kerneldump --output /evidence/new_collection --pod <전체_Pod_UID> --max-write-mbps 200
# Pod 프로세스가 모두 종료된 경우에도 호스트 뷰에서 노드 전체 커널 수집 허용
sudo ./kerneldump --output /evidence/new_collection --pod <전체_Pod_UID> --allow-exited-pod
```

`/evidence`는 기존 디렉터리, `new_collection`은 새 경로여야 합니다. 기본(프로덕션) 빌드 옵션은 다음과 같습니다.
- `--output NEW_DIR`: 새로 만들 출력 디렉터리
- `--pod FULL_POD_UID`: 추가 실행 코드·소켓·상주 캐시 탐색을 지정한 Pod UID로 좁힘 (기본 커널 메타데이터 필터는 노드 전체 유지)
- `--allow-exited-pod`: 호스트 PID/cgroup 뷰에서 지정 Pod의 생존 프로세스가 없을 때도 노드 전체 커널 수집을 이어서 수행
- `--request-id ID`: 요청 식별 라벨 기록
- `--max-write-mbps 1..10000`: 운영 디스크 I/O 보호를 위해 쓰기 대역폭 상한(1,000,000 B/s 단위) 설정

한 번의 호출 안에서 저장소 쓰기·`SYS_renameat2(..., RENAME_NOREPLACE)`·10% RAM(최소 1 GiB) 여유 공간·BTF 6개 필드·`/proc/kcore`·`/proc/kpageflags` 사전 검사를 수행한 뒤 수집하고, 완료 직후 `verify_fast`로 헤더·원장·플래그 RLE·카운터를 검증합니다. `kcore`/`kpageflags`/읽기 가능한 BTF와 가려지지 않은 `page_offset_base`·`linux_banner` 심볼이 필요하며, 보안 설정을 자동으로 바꾸지 않습니다. [필수 조건과 실패 처리](docs/deployment.md).

이전 v9 기준의 수집·검증 출력 형태 예시입니다.

```json
{
  "status": "complete_for_policy",
  "payload_bytes": 656162816,
  "unavailable_bytes": 0,
  "unprocessed_bytes": 0,
  "errors": []
}
```

[이전 수집 stdout](docs/examples/capture_v9.stdout) · [이전 검증 stdout](docs/examples/verify_v9.stdout).

## Pod 지정 및 v1.4.0 성능·무결성 개선

- **Pod 범위 제한**: `--pod`에는 이름이나 접두어가 아닌 전체 Pod UID를 넣습니다. `/proc/self/ns/{pid,cgroup}`가 호스트 `init_pid_ns`·`init_cgroup_ns`와 일치하지 않으면(예: WSL2 중첩 네임스페이스) 노드 전체 수집으로 조용히 바꾸지 않고 종료 코드 `1`로 거부합니다.
- **4 KiB AVX2 Sparse LiME**: LiME 헤더(`0x4c694d45`)와 논리 오프셋·전체 `lime_sha256` 논리 바이트 스트림은 그대로 유지하되, 본문의 4 KiB 0-페이지는 AVX2 검사 후 `seek`로 건너뛰어 실제 디스크 할당과 I/O를 줄입니다. WSL2(`6.18.33.2`) 실측에서 논리 `1,066,746,240 B` 중 `289,443,840 B` 쓰기를 생략하고 기준판 3단계(`8,347.846 ms`) 대비 `6,101.231 ms`로 단축했으며 `disk_sha256_equals_manifest`와 기준판 전수 검증 모두 통과했습니다.
- **버퍼 재사용 및 캐시 비우기**: `4 MiB` 청크 버퍼 풀(`recycle_tx`/`recycle_rx`)과 `16 MiB` 쓰기 창마다의 `sync_file_range` + `POSIX_FADV_DONTNEED`로 동적 할당과 페이지 캐시 점유를 억제합니다.

## 실행 코드·통신·파일 캐시 (이전 v1.3.0 도입 범위 포함)

`kernel-focused` 정책은 별도 옵션 없이 다음 내용을 추가 보존합니다.

- **실행 코드**: private 실행 영역의 익명 페이지. 파일 코드를 수정한 사본과 파일 없이 만든 실행 코드가 포함됩니다. 현재 쓰기 권한은 필요하지 않습니다. 정상 JIT도 포함되므로 수집 자체는 공격 판정이 아닙니다.
- **통신 대기 내용**: 열린 파일에서 찾은 소켓의 수신·송신 큐, TCP 재전송·순서 외 수신 트리, UDP의 별도 읽기 대기 목록(`reader_queue`). 큐마다 최대 64KiB를 고르고, 여러 페이지의 조각과 `frag_list`도 따라갑니다. 과거의 전체 통신은 아닙니다.
- **일부 파일 캐시(Pod 지정 시 보완)**: 열린 memfd·tmpfs 파일과 삭제 후 열린 일반 파일 앞 64KiB까지, 닫힌 공유 memfd(VMA와 `address_space.i_mmap`·proc maps 대조), 실행 코드 비교용 파일 페이지를 찾습니다. FD·maps·VMA·COW 작업은 종류마다 최대 128개, 역방향 VMA는 64개, maps 읽기는 주소 공간당 512KiB(캐시 예산 100ms·4MiB)로 제한합니다.
- **공통 상한**: 코드·네트워크·캐시는 중복 제거 합계 **4,096페이지(본문 최대 16MiB)**를 공유하며 세 종류에 번갈아 기회를 줍니다. 한도에 닿거나 참조가 전후로 바뀌면 `partial`로 남깁니다. 자세한 판단과 실측은 [수집 범위와 비용](docs/resource_retention.md)과 [코드 · 기능 기준 문서](docs/CODEBASE_GUIDE.md)를 참고하세요.

## 이전 빌드 실측 및 비교 기록

### v4 대 v9 추가 수집 비용 (이전 빌드 기록)

익명 실행 페이지·네트워크·캐시의 추가 탐색이 없던 **v4**와 **v9**을 같은 VM·같은 시험 자료·같은 저장소에서 비교한 이전 기록입니다(구성별 3회 중앙값).

| 항목 | 원본 v4 | v9 · Pod 미지정 | v9 · Pod 지정 |
|---|---:|---:|---:|
| 수집 시간 | 10.11 s | 9.88 s | 9.72 s |
| 최종 LiME 파일 | 617.64 MiB | 615.01 MiB | 621.64 MiB |
| 원장·manifest 포함 | 622.97 MiB | 620.28 MiB | 626.58 MiB |
| CPU 시간 합 | 9.06 s | 9.90 s | 9.25 s |
| 최대 수집기 메모리 | 11.00 MiB | 11.25 MiB | 11.38 MiB |
| 기존 필터에 더한 본문 | 0.00 KiB | 8.00 KiB | 28.00 KiB |
| 수집 상태 | 완료 3/3 | partial 3/3 | 완료 3/3 |

[조건·한계·실행별 수치](docs/original_comparison.md).

### 과거 릴리즈 검증 환경 (v4 기록)

아래 표는 추가 수집 이전 v4의 기록이며, 새 BTF 자원 탐색이나 `v1.4.0` 호스트 `--pod` 검증으로 확대하지 않습니다.

| 환경 | 커널 | 결과 |
|---|---|---|
| Ubuntu 24.04.5 | 6.8.0-147 | ext4에서 수집·검증 성공 |
| Ubuntu 26.04, WSL2 | 6.18.33.2 | ext4에서 수집·검증 성공 |
| Debian 12 | 6.1.0-53-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Debian 13 | 6.12.111+deb13-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Rocky Linux 8.10 | 4.18.0-553.el8_10.x86_64 | 수집·검증 성공; xfs, cgroup v1 |
| Rocky Linux 9.8 | 5.14.0-687.10.1.el9_8.0.1.x86_64 | 수집·검증 성공; xfs, cgroup v2 |
| Kali Rolling (cloud 2026.2) | 6.18.12+kali-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Alpine 3.16.9, cgroup v1 | 5.15.148 | 실행 가능, kcore 부재로 수집 불가 |
| Alpine 3.22.6, cgroup v2 | 6.12.110 | 실행 가능, kcore 부재로 수집 불가 |

[검증 조건](docs/distro_validation.md).

### AWS 비교 (v0.1.1 이전 기록)

AWS EC2 `r6i.2xlarge`(Amazon Linux 2023, Linux 6.18.54, RAM 61.78 GiB, gp3)에서 16 GiB 할당 후 측정한 이전 기록입니다. makedumpfile 시간에는 수집 후 sync가 포함되지 않습니다. [측정 방법과 원자료](docs/benchmark_summary.md).

| 도구 | 횟수 | 이미지 크기 | 명령 경과 시간 | 호스트 캐시 증가 |
|---|---:|---:|---:|---:|
| LiME, 전체 RAM | 1 | 62.965 GiB | 466.93 s | 40.19 GiB |
| makedumpfile `-d 31` | 5 | 2.37 ± 0.62 GiB | 1.48 ± 0.25 s* | 2.37 ± 0.62 GiB |
| **KernelDump** | **5** | **1.99 ± 0.17 GiB** | **20.84 ± 1.78 s** | **110 ± 65 KiB** |

### Volatility 3 분석 호환 한계

Volatility **2.28.0**(Debian 12 / Linux `6.1.0-53`) 시험 결과입니다. [59개 실행 결과와 원인 상세](docs/plugin_compatibility.md).

| 결과 | 플러그인 | 확인 내용 |
|---|---|---|
| 커널 메타데이터 확인 | `pslist`, `pstree`, `sockstat`, `lsof`, `lsmod`, `mountinfo`, `ip`, `kmsg`, `ebpf` | 전체본과 같은 레코드; 시험 소켓 5개 모두 유지 |
| 프로세스 메모리 내용 제외 | `psaux`, `envars`, `elfs`, `library_list`, `vmaregexscan` | 인자·환경변수·ELF 헤더·프로세스 버퍼는 수집 정책에서 제외 |
| 불완전한 입력으로 결과 변화 | `process_spoofing` | 명령행 부재로 `True`가 `False`로 바뀔 수 있음; `False`는 위장 없음의 근거가 아님 |
| 파일 메타데이터 보존, 내용 제한 | `pagecache.Files`, `pagecache.RecoverFs` | 경로·inode는 일치하지만 제외한 파일 캐시 때문에 내용의 완전한 복구는 불가 |
| 미수집 구간의 분석 호환성 한계 | `psscan` | 제외한 페이지 공백을 읽을 때 누락 페이지 예외 미처리로 스캔 중단; `pslist`로 대체 불가 |
| 전체 RAM에서도 실패 | `sockscan`, `capabilities`, `kallsyms` | 분석기 오류로, 선별 때문이라고 단정할 수 없음 |

(주: 전용 분석기 `rrudrok`은 KernelDump v1.4.0 Sparse `memory.lime`과 `ranges.jsonl`을 `analyze --verify-hashes`·`show`·`read-memory`로 직접 처리합니다.)

## 산출물과 종료 상태

- `memory.lime`: 물리 주소를 유지한 Sparse LiME 선별 메모리.
- `ranges.jsonl`: 수집·제외·읽기 실패 범위 원장.
- `manifest.json`: 정책, 원본 식별 정보, `allocated_file_bytes`·`sparse_zero_hole_bytes`·`actual_written_bytes`, 오류와 파일 해시.

종료 **0**은 기록된 정책에 따른 수집·저장·사후 검증 완료, **2**는 불완전 수집 또는 준비 실패, **1**은 명령·준비·네임스페이스·검증·저장 오류입니다. 수집은 원자적이지 않으며 취소는 협력적입니다.

## 빌드와 확인

```sh
./kerneldump --version
./kerneldump --build-info
cargo test --offline --locked
python3 scripts/build_release.py --check-vendor
python3 scripts/build_release.py
```

버전 **1.4.0**. `release/kerneldump`, `release/manifest.json`, `release/SHA256SUMS.txt`를 만듭니다. 빌드 정보에는 소스 해시와 실제 실행 파일의 해시가 기록됩니다. [코드 · 기능 기준](docs/CODEBASE_GUIDE.md) · [개발 옵션](docs/development_options.md) · [릴리즈 검증](docs/release_validation.md) · [이전 문서](docs/history_readme_20261017_ko.md).

MIT 라이선스이며, vendored 의존성은 각 라이선스를 유지합니다.

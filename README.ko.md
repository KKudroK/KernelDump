# KernelDump

[English](README.md) · [배포 조건](docs/deployment.md) · [측정 상세](docs/benchmark_summary.md)

`kerneldump`는 `/proc/kcore`와 `/proc/kpageflags`로 실행 중인 커널 메모리를 선별 수집합니다. 커널 모듈 설치나 프로세스 정지 없이 LiME 이미지, 주소·수집 범위 원장과 manifest를 만듭니다.

## 실행

Linux x86-64 정적 바이너리 하나로 실행합니다. 수집 시 별도 런타임 라이브러리·심볼·설정 파일이 필요하지 않습니다.

```sh
chmod 755 kerneldump
sudo ./kerneldump check --target-dir /evidence --json
sudo ./kerneldump capture --output /evidence/new_collection
./kerneldump verify /evidence/new_collection
```

`/evidence`는 기존 디렉터리, `new_collection`은 새 경로여야 합니다. `check`는 커널 접근과 임시 파일 생성·동기화·정리를 검사합니다. 저장소를 지정하지 않거나 검사에 실패하면 준비 실패를 반환합니다. 검사 통과는 공간 예약을 뜻하지 않습니다.

kcore/page monitor를 제공하는 커널과 필수 인터페이스·가려지지 않은 심볼에 대한 읽기 권한이 필요합니다. kcore가 없는 환경은 지원하지 않으며 보안 설정을 자동 변경하지 않습니다. [필수 조건과 실패 처리](docs/deployment.md).

Ubuntu 24.04.5에서 실행한 v0.1.1의 실제 출력입니다. JSON을 읽기 좋게 정렬하고 manifest 경로와 이미지 해시만 생략했습니다.

```json
{
  "status": "complete_for_policy",
  "payload_bytes": 715538432,
  "elapsed_s": 2.418713536,
  "unavailable_bytes": 0,
  "unprocessed_bytes": 0,
  "errors": []
}
```

같은 수집본의 검증 결과:

```json
{
  "verified": true,
  "status": "complete_for_policy",
  "coverage_ranges": 14337,
  "payload_bytes": 715538432
}
```

[수집 stdout](docs/examples/capture.stdout) · [검증 stdout](docs/examples/verify.stdout).

## 검증한 환경

아래 환경에 동일한 x86-64 릴리즈 바이너리를 사용했습니다.

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

Rocky는 SELinux Enforcing을 유지하고 unconfined 도메인에서 sudo로 실행했습니다. Alpine은 kcore가 없었고, WSL의 Windows 공유 저장소는 사적 권한 검사에 실패했습니다. [검증 조건](docs/distro_validation.md).

Kali cloud 이미지의 배포명은 2026.2이며, 내부 `VERSION_ID`는 2026.1입니다.

## AWS 비교

AWS EC2 `r6i.2xlarge`에서 측정한 기록입니다. Amazon Linux 2023, Linux 6.18.54, RAM 61.78 GiB, gp3 저장소를 사용했습니다. 16 GiB를 할당해 페이지마다 쓴 뒤 메모리에 유지했습니다. 반복 측정값은 평균 ± 표본 표준편차입니다.

| 도구 | 횟수 | 이미지 크기 | 명령 경과 시간 | 호스트 캐시 증가 |
|---|---:|---:|---:|---:|
| LiME, 전체 RAM | 1 | 62.965 GiB | 466.93 s | 40.19 GiB |
| makedumpfile `-d 31` | 5 | 2.37 ± 0.62 GiB | 1.48 ± 0.25 s* | 2.37 ± 0.62 GiB |
| **KernelDump** | **5** | **1.99 ± 0.17 GiB** | **20.84 ± 1.78 s** | **110 ± 65 KiB** |

KernelDump 이미지는 전체 RAM LiME보다 **96.8% 작았고**, 관측된 캐시 증가가 작으며 별도 LiME 변환이 필요하지 않았습니다.

*makedumpfile 시간에는 수집 후 sync가 포함되지 않고, KernelDump에는 내구 저장 완료가 포함됩니다. 따라서 같은 저장 완료 기준의 속도 비교는 아닙니다. 수집 정책과 시점도 다르며, AWS 측정은 v0.1.1 이전 기록입니다. [측정 방법과 원자료](docs/benchmark_summary.md).

## Volatility 3 분석

Volatility **2.28.0**, Debian 12 / Linux **6.1.0-53**, 일치하는 DWARF 심볼과 4단계 페이지 테이블에서 시험했습니다. 전체본과 그 바이트를 그대로 선별한 수집본을 비교해 선별 손실과 분석기 오류를 구분했습니다.

| 결과 | 플러그인 | 확인 내용 |
|---|---|---|
| 커널 메타데이터 확인 | `pslist`, `pstree`, `sockstat`, `lsof`, `lsmod`, `mountinfo`, `ip`, `kmsg`, `ebpf` | 전체본과 같은 레코드; 시험 소켓 5개 모두 유지 |
| 프로세스 메모리 내용 제외 | `psaux`, `envars`, `elfs`, `library_list`, `vmaregexscan` | 인자·환경변수·ELF 헤더·프로세스 버퍼는 수집 정책에서 제외 |
| 불완전한 입력으로 결과 변화 | `process_spoofing` | 명령행 부재로 `True`가 `False`로 바뀔 수 있음; `False`는 위장 없음의 근거가 아님 |
| 파일 메타데이터 보존, 내용 제한 | `pagecache.Files`, `pagecache.RecoverFs` | 경로·inode는 일치하지만 제외한 파일 캐시 때문에 내용의 완전한 복구는 불가 |
| 미수집 구간의 분석 호환성 한계 | `psscan` | 누락 페이지 읽기 예외로 스캔 중단; 실제 릴리즈 수집본에서도 재현 |
| 전체 RAM에서도 실패 | `sockscan`, `capabilities`, `kallsyms` | 분석기 오류로, 선별 때문이라고 단정할 수 없음 |

`malfind`, `check_creds` 등의 빈 출력은 탐지 성공으로 세지 않았습니다. 분석에는 커널에 맞는 심볼이 필요하며, 수집은 여전히 실행 파일 하나로 가능합니다. [59개 실행 결과와 원인 상세](docs/plugin_compatibility.md).

**`psscan`의 한계:** KernelDump가 제외한 페이지는 수집본에 공백으로 남습니다. 동일 바이트 비교에서는 Volatility가 잘못된 프로세스 후보를 검사하다 이 공백을 읽었고, 누락 페이지 예외를 처리하지 않아 스캔이 중단됐습니다. 전체본에서 해당 후보의 종료 상태와 PID는 `-1`이었으므로, 이 최초 실패가 실제 유효 프로세스 누락을 뜻하지는 않습니다. 공백은 KernelDump의 선별로 생기고, 분석 전체 중단은 분석기의 공백 처리에서 발생합니다. 선별본의 `psscan` 동작은 보장하지 않으며, `pslist`도 숨김·잔존 프로세스 검색을 대신하지 않습니다. 이 오류를 피하려고 주변 페이지나 수집 옵션을 추가하지 않습니다.

## 산출물과 종료 상태

- `memory.lime`: 물리 주소를 유지한 선별 메모리.
- `ranges.jsonl`: 수집·제외·읽기 실패 범위.
- `manifest.json`: 정책, 원본 식별 정보, 오류와 파일 해시.

종료 **0**은 기록된 정책에 따른 수집·저장 완료, **2**는 불완전 수집 또는 준비 실패, **1**은 명령·준비·검증·저장 오류입니다. stderr와 일부 파일을 보존하세요. 수집은 원자적이지 않으며 취소는 협력적입니다. SIGKILL 뒤에는 최종 manifest가 없을 수 있습니다.

## 빌드와 확인

```sh
./kerneldump --version
./kerneldump --build-info
# 빌드 호스트에만 Rust 1.90.0 + x86_64-unknown-linux-musl 타깃 필요
python3 scripts/build_release.py
```

버전 **0.1.1**. `release/kerneldump`와 선택적인 해시 증적을 만듭니다. 빌드 정보에는 소스 해시와 실제 실행 파일의 해시가 기록됩니다. [릴리즈 검증](docs/release_validation.md) · [이전 문서](docs/history_readme_20261017_ko.md).

MIT 라이선스이며, vendored 의존성은 각 라이선스를 유지합니다.

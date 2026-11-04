# 시나리오 2: 닫힌 FD memfd 수집 보완

2026-11-04. 시나리오 2 채팅에서 확인한 기존 memfd VMA 수집 변경을 바탕으로 탐색 예산, 프로세스 연결 검증과 회귀 테스트를 보완했다.

## 변경 내용

- 선택한 Pod의 공유 memfd는 FD를 닫았어도 VMA, vm_file, address_space.i_mmap과 i_pages를 통해 현재 상주 내용을 찾는다.
- proc maps 읽기를 소켓 탐색 이후 캐시 단계로 옮겼다. 동일한 mm은 한 번만 예약하며, 주소 공간마다 512KiB 한도를 적용한다. proc 읽기 요청도 캐시의 4MiB와 100ms 예산에 포함한다.
- maps 경로의 첫 구성요소가 /memfd:로 시작하는 공유 매핑만 후보로 삼는다. 범위, 파일 오프셋, inode 번호를 커널 VMA와 대조하고, 링크 없는 일반 shmem 파일인지 확인한다. 이름만으로 악성 여부나 생성 이력을 판정하지 않는다.
- i_mmap에서 찾은 주소 공간을 task 주소, PID, 시작 시간과 연결한다. task.mm과 프로세스 식별값을 발견 시 확인하고, 파일 본문 읽기 전후의 원장 검증에도 포함한다.
- 역방향 목록에 공유 또는 사유 매핑 여부와 파일 바이트 범위를 기록한다. 소유자 목록이 비어 있으면 미확인이며, 사용자가 없다는 뜻이 아니다.
- 확장된 작업 큐에서도 총 128개 작업 한도를 적용한다. 기존 FD와 실행 코드 비교 캐시 작업을 먼저 처리한다.

전체 수집 정책은 kernel-focused-v9를 유지한다. 이 추가 경로는 --pod로 지정한 Pod에서 발견한 공유 memfd를 출발점으로 사용한다. 역방향 연결에는 같은 파일을 매핑한 다른 프로세스도 나타날 수 있다. 프로세스 리더 인덱스와 기존 탐색 한도 때문에 모든 스레드와 과거 사용자를 보장하지 않는다.

## 검증

오프라인 production release 테스트 82개가 모두 통과했다. 새 회귀 테스트 7개는 다음 경우를 검사한다.

1. maps 경로와 공유 여부 및 필드의 유효성.
2. FD 테이블 없이 공유 memfd와 소유자 두 명을 찾고, 소유자 mm 변경 시 검증 실패.
3. inode 불일치 또는 사유 VMA인 출발점에서 본문 추가 방지.
4. 역방향 트리 순환, 출발 VMA 부재, PID 변경 거부.
5. 알 수 없는 소유자와 사유 매핑 및 다른 파일 오프셋의 명시적 기록.
6. proc 읽기 지연, 동일 mm 중복 제거, 크기 및 시간과 읽기 예산 한도.
7. 대기 큐를 비운 뒤에도 총 작업 수 한도 유지.

    cargo test --release --locked --offline --target x86_64-unknown-linux-musl
    python3 scripts/build_release.py --output /out/release

새 정적 바이너리 SHA-256:

    00ab40c3569bf9d21ab80327b2f13bf8d8f3056cc2ccca62ca9d8bfddea40591

실제 Ubuntu 7.0.0-38-generic 커널을 로컬 QEMU에서 부팅해 새 덤프를 수집했다. VM은 RAM 1GiB, vCPU 2개이며 네트워크가 없다. 실제 cgroup2에 정확한 Pod UID 경로를 만든 검증 환경으로, Kubernetes 또는 EKS 실행은 아니다.

| 확인 항목 | 결과 |
|---|---|
| 새 Pod 범위 덤프 | complete_for_policy, verify 성공 |
| 새 노드 범위 대조 덤프 | complete_for_policy, verify 성공 |
| memfd FD | 세 프로세스 모두 닫힘 |
| 역방향 매핑 | 공유 2개, 사유 1개 |
| 연결된 호스트 PID | 93, 96, 97 |
| 공유 파일 본문 | 8,192바이트 복원, 요청 및 응답 일치 |
| 사유 COW 내용 | 공유 파일 본문과 혼동하지 않음 |
| 커널 객체 원본 바이트 | i_mmap 트리, VMA, task.mm, PID, 시작 시간 모두 기록과 일치 |
| 소켓 대조 데이터 | Pod 범위와 노드 범위 모두 복원 |
| 캐시 추가 후보 | 관리 정보 포함 15페이지 |
| 캐시 읽기 요청 | 총 25,831바이트, proc maps 24,576바이트 포함 |
| 캐시 탐색 시간 | 12,734,021ns, 소프트웨어 에뮬레이션 관측값 |

커널 BTF SHA-256은 2b91134c0f8fdf86be01ddf92bd7bb12393b0137aedd190556d0f26bddddd12b이다. 수집 전후 모든 기록된 resource same_fields 검증이 통과했다. 노드 범위 대조에서는 memfd proc 탐색이 실행되지 않았다.

시나리오 2의 기존 EKS static-smoke 덤프도 새 실행 파일의 verify로 다시 확인했다. 이는 무결성과 형식 호환성 검증이며, 새 바이너리를 EKS에서 다시 실행한 결과는 아니다. 기존에 제외된 바이트를 사후에 복원한다는 뜻도 아니다.

## 결과 파일과 해석 범위

구조화된 결과는 scenario2_memfd_20261104_validation.json에 있다. 재현용 fixture.c, init, prepare_vm.sh, analyze.py, btf_probe.rs, build.log와 실제 덤프는 다음 실험 폴더에 보존했다.

    C:\Users\ohnah\Desktop\공격_시나리오\kerneldump-scenario2-fix-20261104

검증된 production 바이너리는 release/kerneldump이며 manifest.json과 SHA256SUMS.txt도 갱신했다. 시나리오 2가 배포했던 이전 실행 파일은 실험 폴더의 before-install/release에 보존했다.

살아 있는 매핑을 비원자적으로 읽는 수집이다. 범위가 겹치는 공유 매핑은 데이터 교환 가능성을 나타내며, 과거 통신이나 상대 프로세스의 처리 완료를 증명하지 않는다. 탐색 요약은 발견 시점의 관측이므로 원장의 검증 결과와 함께 해석해야 한다. 파일 64KiB, 역방향 VMA 64개, 캐시 작업 128개 및 기존 페이지 예산은 유지된다. 단일 에뮬레이션 측정으로 성능 개선을 주장하지 않는다.

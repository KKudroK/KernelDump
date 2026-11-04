# 7.0.0-38-generic 실제 커널 검증

2026-11-04에 기존 덤프 2개와 새 수집본 3개를 최종 실행 파일로 검증했다. 새 수집은 공식 Ubuntu 7.0.0-38.38 커널을 부팅한 로컬 QEMU VM에서 수행했다. 기존 덤프와 새 VM의 GNU Build ID 및 BTF SHA-256이 모두 일치했다.

## 결과

| 시험 | 결과 |
|---|---|
| 기존 정상 및 변조 후 v5 덤프 | 두 덤프 모두 최종 검증기 통과 |
| 새 Pod UID cgroup 범위 수집 | complete_for_policy, 실행 페이지 4KiB, 소켓 16KiB, 파일 캐시 8KiB의 원본 바이트 일치 |
| 새 노드 범위 수집 | complete_for_policy, 실행 페이지 4KiB와 소켓 16KiB 일치 |
| 128개 프로세스가 공유하는 코드 페이지가 있는 노드 수집 | complete_for_policy, 기존 단일 프로세스 포함 총 코드 참조 4,097개, 코드 33페이지와 소켓 32KiB 일치 |
| 큰 범위 기록 | 최대 1,639,003바이트의 실제 기록이 수집 및 검증을 통과 |
| 실제 FD 종료 | 같은 프로세스가 dup으로 소켓을 유지한 채 기록된 FD만 닫자 네트워크 참조 검사 실패 및 complete=false 확인 |
| 완료 상태 및 증거 기록 모순 | 실제 덤프의 복사 메타데이터를 바꾼 7종 모두 거부, 정상 대조군 통과 |
| 자동 테스트 | 일반 및 개발 옵션 구성에서 각각 75개 통과 |

코드와 소켓 바이트는 ranges.jsonl의 물리 주소와 LiME 오프셋을 따라 직접 읽어 시험 자료와 대조했다. 소켓의 PID, task.files, files_struct.fdt, FD 표, 열린 비트, file, socket, sock 연결도 덤프의 실제 바이트와 BTF 필드로 확인했다. FD 종료 음성 시험은 같은 자원 검사 코드를 호출하는 별도 테스트 하네스에서 실행했다. 이 하네스는 배포 실행 파일과 구분해 보존했다.

## 새로 발견하여 수정한 호환성 문제

첫 실행에서 노드 수집은 완료됐지만 Pod 파일 캐시 수집은 page.index를 찾지 못해 partial이 됐다. 실제 BTF에서 page.__folio_index와 folio.index를 확인했다. 파일 위치는 folio.index로 읽도록 수정했다. 큰 folio의 페이지 수도 새 이름인 folio._nr_pages와 이전 이름인 folio._folio_nr_pages를 BTF로 구분한다. 고정 오프셋은 추가하지 않았다.

이 구조 차이는 [Linux 7.0의 정의](https://github.com/torvalds/linux/blob/v7.0/include/linux/mm_types.h)와 [Linux 6.8의 정의](https://github.com/torvalds/linux/blob/v6.8/include/linux/mm_types.h)에서도 확인된다. 구버전과 신버전 BTF 형태 각각에서 큰 folio의 두 번째 페이지를 찾고, 파일 위치 변경 시 증거를 무효화하는 회귀 테스트를 추가했다. 수정 후 동일 커널의 새 VM에서 세 수집이 모두 완료됐다.

## 식별자와 재현 자료

- 커널: 7.0.0-38-generic x86_64
- GNU Build ID: 338e542e384c46228f7a378babc0f9bb2b6a5997
- BTF SHA-256: 2b91134c0f8fdf86be01ddf92bd7bb12393b0137aedd190556d0f26bddddd12b
- 최종 실행 파일 SHA-256: 5a3c8be806bb36e47151fb6d753aa0a25e53e0eeae881b444a34d2ec72abe1f2
- [기계 판독 결과](kernel_7_0_0_38_validation.json)
- [배포 실행 파일 출처](../release/manifest.json)

시험 스크립트, 수정 전 실패 덤프, 최종 덤프, 가상 디스크와 로그는 C:\Users\ohnah\Desktop\공격_시나리오\validate-kerneldump-7.0.0-38-20261104에 보존했다. [Ubuntu 공식 커널 패키지](https://packages.ubuntu.com/resolute-updates/linux-image-7.0.0-38-generic)를 사용했다. VM은 시험 종료 후 전원이 꺼졌으며 실행 컨테이너도 종료했다.

## 적용 범위

시험 환경은 메모리 1GiB, vCPU 2개, 외부 네트워크 없는 QEMU 소프트웨어 가상화다. Pod 시험은 실제 커널의 cgroup에 정확한 Pod UID 경로를 만든 시험 자료이며 Kubernetes나 EKS 클러스터를 생성한 시험은 아니다. 소켓 본문은 AF_UNIX 대기 데이터다. 모든 네트워크 프로토콜, 다른 파일 시스템과 운영 부하의 호환성을 의미하지 않는다.

첫 실행의 128개 프로세스 Pod 범위 시험에서는 기존 250ms 식별 검증 한도에 도달해 partial이 됐다. 이 결과를 성공으로 바꾸지 않았으며, 한도도 늘리지 않았다. 최종 대량 참조 시험은 노드 범위에서 수행했다. 소프트웨어 CPU 가상화의 시간 측정으로 운영 환경 성능을 주장하지 않는다.

덤프는 비원자적이다. 검사된 연결과 바이트의 일치는 과거 실행, 통신 상대의 수신, 전체 큐 이력이나 ABA 부재를 증명하지 않는다. 기존 덤프 검증은 이전 수집에서 누락된 바이트를 복구하지 않는다.

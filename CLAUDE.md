# CLAUDE.md

이 파일은 Claude Code(claude.ai/code)가 이 저장소에서 작업할 때 참고할 가이드입니다.

## 멀티에이전트 작업 (cmux native)

- 기동: `cmux claude-teams --model sonnet` (또는 cmux command palette `⌘K` → `Claude Teammate Mode`)
- 워커는 현재 cmux 워크스페이스 내 native split으로 자동 등장 (tmux/omc-watch 불필요)
- 필수 env: `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` (`~/.zshrc` 에 이미 설정)
- 빌드/플래시/UART 캡처는 `cmux.json` 팔레트 항목 사용 (`Build → Flash → UART Capture` 원클릭)
- CRITICAL 리뷰 finding 발견 시 즉시 중단 후 사용자 보고
- **병렬 워커 spawn 시 항상 cmux 화면을 스플릿해서 보여줄 것** — 사용자가 별도 요청하지 않아도 기본 동작

## Git 워크플로 & Issue 추적

- **Issue 먼저 생성**: `gh issue create --title "..."` → #N 번호 부여
- **브랜치명 규칙**: `feat/#N-slug` / `fix/#N-slug` (예: `feat/#2-repeat-count-100`)
- **커밋 형식**: `feat(scope): 설명 (#N)` (Conventional Commits)
- **PR 본문**: `Closes #N` 포함 → merge 시 Issue 자동 닫힘
- 상세 규칙: `GIT_WORKFLOW.md` 참조

## 빌드 및 플래시

```bash
# 최초 1회 설정
cmake --preset Debug      # 또는 Release

# 빌드
cmake --build build/Debug

# SWD를 통해 STM32F439ZI에 플래시 (전체 경로 필요 — PATH 미등록)
/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/Resources/bin/STM32_Programmer_CLI \
  -c port=SWD -w build/Debug/Test_pqc_tls.elf -rst
```

**UART 시리얼 포트**: `ls /dev/cu.*` 로 확인 (보통 `/dev/cu.usbmodemXXXX`, 재연결 시 번호 바뀜)

**툴체인**: `arm-none-eabi-gcc`, Cortex-M4F 하드-플로트(`-mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard`)
**빌드 생성기**: Ninja, C11 표준
**링커 옵션**: `--specs=nano.specs`(Newlib-nano, 소형 C 라이브러리) + `-u _printf_float`(float printf 포함)

## 아키텍처

**타겟 보드**: NUCLEO-F439ZI (STM32F439ZI, Cortex-M4F @ 168 MHz, Flash 2 MB, SRAM 192 KB, CCM RAM 64 KB)

**프로젝트 목적**: 데스크탑 TLS 서버를 상대로 **포스트 양자(PQC) 및 하이브리드 인증서 기반 TLS 1.3 핸드셰이크 성능을 벤치마킹**하는 임베디드 클라이언트

### 런타임 스택 구성

```
FreeRTOS (Heap_5: CCM 56 KB + SRAM 138 KB = 194 KB 통합 힙)
├── defaultTask  (4 KB 스택)   — LwIP/DHCP 초기화, 시스템 모니터링
├── tlsPerf      (16 KB 스택)  — TLS 1.3 핸드셰이크 벤치마크 (메인 워크로드)
├── certBench    (16 KB 스택)  — 인증서 전송/검증 벤치마크 (대체 워크로드)
└── wolfCrypt    (35 KB 스택)  — 데모 태스크 (힙 절약을 위해 보통 비활성화)

LwIP v2.1.2     — Ethernet RMII 위의 TCP/IP 스택 (DHCP 활성화, LAN8742A PHY)
wolfSSL 5.8.4   — PQC 확장이 포함된 TLS 1.3
```

### PQC 알고리즘 및 인증서 시나리오

wolfSSL 설정은 `wolfSSL/wolfSSL.I-CUBE-wolfSSL_conf.h`에 있으며 다음과 같습니다:
- **ML-DSA (Dilithium)**: 키생성/서명/검증 모두 지원, 소형 메모리 검증 경로 사용 (`WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM`)
- **Falcon**: 검증 전용 (512 L1, 1024 L5)
- **SPHINCS+**: 검증 전용 (SHAKE-128f-simple L1)
- **ML-KEM (Kyber)**: 현재 설정에서 비활성화 (`WOLF_CONF_KYBER=0`)
- **하이브리드 인증서**: `WOLFSSL_DUAL_ALG_CERTS`, `WOLFSSL_HYBRID_CERT`, `WOLFSSL_COMPOSITE_CERTS`
- 하드웨어 암호화(CRYP/HASH)는 **비활성화** — 플랫폼 간 일관된 측정을 위해 소프트웨어 구현만 사용

TLS 클라이언트(`tls_client.c`)는 **9종 인증서 타입 × 3 보안 레벨 = 25개 활성 시나리오**를 벤치마크합니다:

| 타입 | 방식 | 포트 |
|------|------|------|
| ECDSA | 순수 고전 암호 (P-256/384/521) | 11101/11103/11105 |
| ML-DSA | 순수 PQC (ML-DSA44/65/87) | 11111/11113/11115 |
| Catalyst | 단일 인증서, EC 주키 + ML-DSA 대체키 (SubjectAltPublicKeyInfo) | 11121/11123/11125 |
| Chameleon | DCD 모델, EC와 ML-DSA 체인 모두 검증 | 11131/11133/11135 |
| Related | ECDSA + ML-DSA 듀얼 체인, RelatedCertificate 확장 포함 | 11141/11143/11145 |
| Dual | 하나의 Certificate 메시지에 두 체인 동시 포함 | 11151/11153/11155 |
| Composite | OQS-OpenSSL 결합 서명 방식 | 11161/11163/11165 |
| Falcon | Falcon-512/1024 (L1/L5만 존재) | 11171/11175 |
| SPHINCS+ | SPHINCS+-SHAKE-128f (L1만 존재) | 11181 |

### 벤치마크 동작 흐름

1. 보드 부팅 → DHCP로 IP 획득 → SNTP로 시간 동기화
2. `tlsPerf` 태스크가 시나리오를 순회하며 TLS 서버(**192.168.0.27**)의 시나리오별 포트로 접속
3. 각 시나리오마다 **20회 핸드셰이크**(`TLS_REPEAT_COUNT`) 수행하며 단계별 타이밍 측정:
   - ServerHello 수신, Certificate 체인 수신, CertVerify, PQCertVerify, Finished
4. 평균·표준편차·95% 신뢰구간 결과를 **UART3 @ 115200 baud**로 출력

⚠️ 데스크탑(192.168.0.27)에서 모든 포트/인증서 시나리오가 설정된 TLS 서버가 실행 중이어야 합니다.

## 주요 파일

| 파일 | 역할 |
|------|------|
| `Core/Src/tls_client.c` | TLS 1.3 핸드셰이크 벤치마크 — 25개 시나리오, 내장 루트 CA, 단계별 타이밍 |
| `Core/Inc/tls_client.h` | 서버 IP/포트 설정, 인증서 타입 enum, 측정 횟수 정의 |
| `Core/Src/cert_bench.c` | 독립형 인증서 전송·서명 검증 벤치마크 |
| `Core/Src/wolfssl_hybrid.c` | 하이브리드 인증서 타입 설정 함수, RelatedCertificate 검증 |
| `Core/Src/main.c` | HAL 초기화, FreeRTOS 태스크 생성, UART3 printf 리다이렉션 |
| `Core/Src/heap_regions.c` | FreeRTOS Heap_5 메모리 영역 설정 (CCM + SRAM) |
| `wolfSSL/wolfSSL.I-CUBE-wolfSSL_conf.h` | wolfSSL/PQC 알고리즘 on/off, 버퍼 크기, 메모리 최적화 옵션 |
| `STM32F439XX_FLASH.ld` | 메모리 레이아웃 (Flash 2 MB, RAM 192 KB, CCMRAM 64 KB) |
| `Test_pqc_tls.ioc` | STM32CubeMX 프로젝트 파일 — 주변장치/클럭 수정 시 CubeMX로 재생성 필요 |
| `cmake/stm32cubemx/CMakeLists.txt` | 자동 생성된 CMake 규칙 — 모든 소스/인클루드 경로 정의 |

## 메모리 제약 사항

- SPHINCS+ fast-L5의 약 50 KB 서명을 수용하기 위해 핸드셰이크 버퍼를 **65536 바이트**로 설정
- ML-DSA87 검증은 약 60 KB가 필요 → `WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM`을 사용해 행렬 A를 열 단위로 처리(약 12 KB)
- FreeRTOS 힙을 CCM(고속, DMA 불가)과 SRAM(DMA 가능) 두 영역으로 나눠 `heap_regions.c`에서 등록
- 파일시스템 없음 — 모든 루트 CA 인증서는 `tls_client.c`에 PEM 문자열로 내장
- RAM 절약을 위해 `NO_SESSION_CACHE`, `NO_PSK` 설정 적용

## LwIP & TLS 운영 주의사항

### lwipopts.h 핵심 제약
- **`LWIP_SO_RCVTIMEO=1` 필수** — 없으면 `setsockopt(SO_RCVTIMEO)` 가 compile-time no-op (기본값 0)
- `TCP_WND` ≤ `PBUF_POOL_SIZE × effective_pbuf_size` — LwIP 빌드 sanity check (위반 시 빌드 에러)
- 현재: `TCP_WND=8×TCP_MSS=11680B`, `PBUF_POOL_SIZE=10` (34KB SPHINCS+ 인증서 burst 수용)

### TLS 서버 관리
- **openssl s_server는 단일 스레드** — 보드 리셋 후 반드시 서버 재시작 (스테일 ESTABLISHED 연결이 새 ClientHello를 블로킹)
- while-loop 래퍼(`trap '' TERM`)로 띄운 서버는 자식 프로세스만 죽여도 재시작됨:
  ```bash
  kill -9 <래퍼_PID>          # 먼저 loop 중단
  lsof -ti :PORT | xargs kill -9  # 자식 정리
  ```
- 연결 상태 확인: `lsof -i :PORT` — ESTABLISHED가 남아 있으면 서버가 SSL_read 대기 중

### SPHINCS+ 타이밍 특성
- STM32 @ 168MHz: SHAKE verify 약 3.2s, 핸드셰이크 전체 약 3.8s
- `SO_RCVTIMEO`는 verify 시간보다 충분히 크게 설정 (현재 20s)
- `sphincs.c` FORS(k)/HT(d) 루프에 `SPX_YIELD()=taskYIELD()` 삽입 필수 — 없으면 LwIP tcpip_thread가 CPU를 받지 못해 TCP 패킷 처리 불가

## 코드 컨벤션

- 타이밍은 `HAL_GetTick()`(1 ms 해상도)을 사용하며, 단계별 서브 타이밍은 `g_tls_t_*` volatile 전역변수에 저장
- 커스텀 TLS 확장:
  - ClientHello 확장 `0xFF10` — 하이브리드 인증서 타입 힌트
  - 타입 250 `PQCertificateVerify` 메시지 — PQ 서명 검증용
- 하이브리드 인증서 OID:
  - RelatedCertificate: `1.3.6.1.5.5.7.1.36`
  - SubjectAltPublicKeyInfo(sapki), AltSignatureAlgorithm, AltSignatureValue
- `syscalls.c`의 `_write()`가 stdout을 UART3로 리다이렉트 → `printf` 기반 로그 출력

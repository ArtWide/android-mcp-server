# Android MCP Server (한국어)

ADB(Android Debug Bridge)를 통해 안드로이드 기기를 제어하고, **정적 분석(JADX)**과
**동적 계측(Frida)**까지 수행하는 MCP(Model Context Protocol) 서버입니다.
Claude Desktop 등 MCP 클라이언트에서 안드로이드 기기 분석 작업을 자동화할 수 있습니다.

> 영문 문서는 [README.md](README.md), 배포·트러블슈팅 상세는
> [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)를 참고하세요.

## 주요 특징

- 🔧 **ADB 명령 실행** — 임의 셸 명령, 패키지 목록, UI 분석, 스크린샷, logcat
- 🧩 **JADX 정적 분석** — APK를 Java로 디컴파일하고 코드 검색
- 🔎 **androguard 정적 분석** — 매니페스트/권한/exported 컴포넌트, 서명, 시크릿 스캔
- 🧱 **apktool** — 리소스·smali 디코딩
- 🧬 **Frida 동적 계측** — 프로세스 attach/spawn, 스크립트 주입, 실시간 메시지
- 🌐 **mitmproxy 네트워크 캡처** — 기기 트래픽 프록시 캡처·조회
- ♻️ **상시 HTTP 서버** — 프로세스가 계속 떠 있어 ADB 연결과 Frida 세션이 유지됨
  (stdio 방식은 클라이언트 연결마다 프로세스가 죽어 장기 세션이 끊김)

## 스킬 (Claude 보조)

`skills/`에 Claude Code/Desktop용 스킬이 있습니다 (전역 `~/.claude/skills/`에 설치 시 자동 적용):
- **android-analysis** — 도구 사용 일반(분석·자동화 워크플로우)
- **malware-analysis** — 드롭퍼 → 페이로드 → C2 방법론 + KVault 검색-우선/카드-제안(그라운딩) + "제안+확정" 모드 + 리포트 템플릿

## 노출되는 도구 (총 52개)

> **frida 버전 주의**: 호스트 frida(파이썬 바인딩)와 기기 frida-server는 **버전이 일치**해야
> 합니다(최소 메이저). 한 서버 프로세스에는 frida 한 버전만 올라가므로, 서로 다른 frida
> 버전이 필요한 기기는 **venv·포트를 분리한 별도 MCP 인스턴스**로 운영하세요.
> `frida_check_compatibility`로 불일치를 사전 진단할 수 있습니다.

### ADB 기기 제어 (14개)

| 도구 | 기능 | 입력 |
|------|------|------|
| `list_devices` | 연결된 기기 목록(시리얼+모델, 활성 표시) | 없음 |
| `select_device` | 활성 기기 런타임 전환 | `serial` |
| `get_current_device` | 현재 활성 기기 조회 | 없음 |
| `get_packages` | 설치된 패키지 전체 목록 | 없음 |
| `execute_adb_shell_command` | 임의 ADB 셸 명령 실행 ⚠️ | `command` |
| `get_uilayout` | 현재 화면의 클릭 가능 UI 요소 + 좌표 | 없음 |
| `get_screenshot` | 화면 캡처 (PNG, 30% 리사이즈) | 없음 |
| `get_package_action_intents` | 앱이 처리하는 Intent action 목록 | `package_name` |
| `get_logcat` | 필터링된 logcat 수집 | `lines`, `filter_spec`, `priority` |
| `push_file` | 호스트 → 기기 파일 전송(샘플/도구/페이로드) | `local_path`, `device_path` |
| `pull_file` | 기기 → 호스트 파일 회수(드롭된 페이로드 등) | `device_path`, `local_path` |
| `install_apk` | 호스트 APK를 기기에 설치(adb install) | `apk_path`, `reinstall`, `grant_permissions`, `downgrade` |
| `install_and_launch` | 기존앱 제거+설치+실행(재서명 APK용) | `apk_path`, `package`, `launch`, `uninstall_existing` |
| `install_user_ca` | mitmproxy CA를 사용자 인증서로 설치(기기서 최종 확인, 비루팅) | `cert_source` |
| `install_system_ca` | **루팅 기기 시스템 트러스트 스토어**에 CA 자동 설치(모든 앱 신뢰, tmpfs 오버레이·되돌리기 가능). HTTPS 복호화 권장 경로 | `cert_source` |
| `check_dynamic_readiness` | 동적 스택 원샷 점검(기기·root·frida 버전·mitmproxy·기기 CA 신뢰·캡처·재패키징) → OK/조치법 | `cert_source` |

### 베이스라인 before/after (2개)

기기를 읽기 전용으로 스냅샷하고 비교해 샘플이 바꾼 것을 드러냅니다. 스냅샷은 workspace에 저장(지식카드 아님).

| 도구 | 기능 | 입력 |
|------|------|------|
| `capture_baseline` | 활성 기기 상태 스냅샷(패키지·프로세스·소켓·device-admin·보안설정·감시 디렉터리 파일). 샘플 실행 **전(`pre`)·후(`post`)** 로 촬영 | `label`, `watch_dirs` |
| `diff_baseline` | 두 스냅샷 비교 → **드롭된 패키지·신규 C2 소켓·device-admin/접근성/알림리스너/기본SMS·dialer 변화**·신규 파일 | `before`, `after` |

### androguard 정적 분석 (4개) — 루팅 불필요

> 입력 `target`은 **설치된 패키지명 또는 로컬 .apk 파일 경로** 둘 다 가능합니다
> (업로드한 드롭퍼·다운로드한 페이로드를 기기 없이 분석). JADX/apktool도 동일.

| 도구 | 기능 | 입력 |
|------|------|------|
| `analyze_manifest` | 권한·**exported 컴포넌트**·debuggable/allowBackup·SDK 레벨 | `target` |
| `apk_info` | 서명 인증서·SHA-256·버전·서명 여부 | `target` |
| `scan_secrets` | dex 문자열에서 API 키·토큰·URL·IP 등 시크릿 스캔 | `target` |
| `apk_dropper_indicators` | 드롭퍼 판정(동적로딩·설치·암호화·**페이로드 URL**) | `target` |

### 리패키징 (2개) — 무루트 계측

| 도구 | 기능 | 입력 |
|------|------|------|
| `repackage_apk_frida` | gadget 삽입(Application `<clinit>`, 멀티덱스) + NSC 사용자CA **병합** + 재빌드 + v1/v2/v3 재서명. arch 미지정 시 활성기기 ABI 자동. 실패 시 전체 로그 반환 | `target`, `arch`, `trust_user_certs`, `gadget_config`, `output_path`, `keep_workdir` |
| `check_repackage_toolchain` | 호스트 준비물(apktool/Java/frida/gadget/서명기) 상태 진단 | 없음 |

> 준비물(frida-gadget `.so` + uber-apk-signer)은 `1-setup_frida_server.ps1 -SetupFridaServer`가 자동 다운로드합니다. 산출물은 `install_and_launch`로 설치·기동 → `frida_attach` → `frida_run_preset('ssl-unpin')`.

### apktool 리소스/smali (3개) — Java 필요

| 도구 | 기능 | 입력 |
|------|------|------|
| `apktool_decode` | APK를 리소스+디코딩 매니페스트+smali로 디코딩 (패키지당 1회 먼저) | `package_name` |
| `apktool_list_files` | 디코딩 결과 파일 목록 | `package_name`, `subdir` |
| `apktool_read_file` | 디코딩 결과 파일 1개 읽기 (매니페스트·xml·smali) | `package_name`, `relative_path` |

### mitmproxy 네트워크 캡처 (5개)

| 도구 | 기능 | 입력 |
|------|------|------|
| `network_start_capture` | mitmdump 기동 + adb reverse + 기기 프록시 설정 | `port` |
| `network_list_flows` | 캡처된 플로우(메서드/상태/URL/크기) 목록 | `limit` |
| `network_get_flow` | 특정 플로우의 헤더+본문(패킷 상세) 조회 | `index` |
| `network_stop_capture` | 캡처 중지·프록시/리버스 해제 | 없음 |
| `network_status` | 캡처 실행 상태 | 없음 |

### 화면 실시간 미러 scrcpy (3개)

분석가 PC에 별도 창으로 기기 화면을 **실시간 저지연 미러**(+조작). Claude 대화창 안이 아니라 호스트 창. scrcpy 설치 필요(`0-setup_environment.ps1 -SetupScrcpy`).

| 도구 | 기능 | 입력 |
|------|------|------|
| `start_screen_mirror` | 활성 기기 화면 실시간 미러 창 띄우기(+선택 녹화 mp4) | `max_size`, `record` |
| `stop_screen_mirror` | 미러 중지(녹화 마무리) | 없음 |
| `screen_mirror_status` | 미러 실행 상태 | 없음 |

### JADX 정적 분석 (4개)

| 도구 | 기능 | 입력 |
|------|------|------|
| `jadx_decompile` | 기기에서 APK를 pull → Java로 디컴파일 (패키지당 1회 먼저 실행) | `package_name`, `include_splits` |
| `jadx_list_decompiled` | 디컴파일된 패키지 목록 | 없음 |
| `jadx_search_code` | 디컴파일된 Java 소스 정규식 검색 | `package_name`, `pattern`, `max_results` |
| `jadx_read_source` | 디컴파일된 소스 파일 1개 읽기 | `package_name`, `relative_path` |

### Frida 동적 계측 (12개)

| 도구 | 기능 | 입력 |
|------|------|------|
| `frida_check_compatibility` | 호스트 frida ↔ 기기 frida-server **버전 일치** 진단 | `server_path` |
| `frida_list_devices` | Frida가 보는 기기 목록 | 없음 |
| `frida_list_processes` | 실행 중인 프로세스 목록 | 없음 |
| `frida_list_applications` | 설치된 앱 목록 | 없음 |
| `frida_attach` | 실행 중 프로세스에 attach → `session_id` | `target` (이름/PID) |
| `frida_spawn` | 앱을 suspend 상태로 spawn → `session_id` | `package_name` |
| `frida_run_script` | JS 계측 스크립트 주입·로드 (spawn이면 resume) | `session_id`, `script_source` |
| `frida_run_preset` | 번들 프리셋 로드(예: `ssl-unpin` — SSL 피닝 우회) | `session_id`, `preset` |
| `frida_read_messages` | 스크립트 `send()`/오류 메시지 수집 | `session_id` |
| `frida_resume` | spawn된 suspend 프로세스 재개 | `session_id` |
| `frida_list_sessions` | 서버가 보유한 활성 세션 목록 | 없음 |
| `frida_detach` | 세션 종료·레지스트리에서 제거 | `session_id` |

### 리포트 그림 (2개) — 보고서 증거 이미지

| 도구 | 기능 | 입력 |
|------|------|------|
| `render_code_image` | 코드 스니펫 → 주석/빨간 박스 PNG(밝은 테마, 인라인 `//`) | `code`, `language`, `highlight_lines`, `annotations`, `title`, `start_line` |
| `render_log_evidence` | 로그/패킷 → 우측 `>>` 주석 컬럼 PNG(어두운 테마, 동적증거용) | `text`, `annotations`, `highlight_lines`, `title`, `start_line` |

> 빈 줄/범위 밖을 가리키는 주석·하이라이트는 자동 제외 → **빈 박스가 생기지 않음**. Cowork 아티팩트 대신 이 도구로 그리면 모든 보고서 그림이 동일한 사내 표준으로 일관됩니다.

> ⚠️ `execute_adb_shell_command`는 기기에 대한 임의 명령 실행이며, Frida까지 더하면
> 사실상 **기기 완전 장악 + 런타임 계측**입니다. 신뢰된 환경·인가된 대상에만 사용하세요.

## 빠른 시작 (원 클릭)

루트의 `start.ps1`(또는 더블클릭용 `start.cmd`) 하나로 **설치 → 커넥터 등록 → 서버 구동**까지
순차 실행합니다. 재실행해도 안전합니다(이미 설치됐으면 설치 생략, 커넥터는 변경 시에만 갱신).

```powershell
powershell -ExecutionPolicy Bypass -File start.ps1
# 루팅 기기 frida까지: -Frida / 포트 변경: -Port 8123 / 서버 미구동: -NoServer
```

탐색기에서 **`start.cmd` 더블클릭**으로도 실행됩니다. 단계별로 직접 실행하려면 아래
`scripts\0~4` 스크립트를 순서대로 쓰면 됩니다.

## 사전 준비

- Python 3.11+, [uv](https://docs.astral.sh/uv/)
- ADB (Android Debug Bridge)
- (정적분석) `androguard` — 프로젝트 의존성(자동 설치, 외부 도구 불필요)
- (JADX / apktool 도구용) JADX, apktool + Java(JRE/JDK 11+)
- (Frida 도구용) 호스트 `frida` 바인딩(프로젝트 의존성) + 기기에 **메이저 버전이 일치하는
  frida-server**(루팅 기기)
- (네트워크 캡처) `mitmproxy` (`winget install mitmproxy`)

### 환경 일괄 설치 (Windows, 관리자 권한 불필요)

```powershell
# 없는 것만(ADB/Java/JADX/Frida) 자동 설치하고 환경변수 설정
powershell -ExecutionPolicy Bypass -File scripts\0-setup_environment.ps1

# 루팅 기기에 frida-server까지 push·기동
powershell -ExecutionPolicy Bypass -File scripts\0-setup_environment.ps1 -SetupFridaServer -StartFridaServer
```

`ADB_PATH` / `JAVA_HOME` / `JADX_PATH` 사용자 환경변수를 설정하므로, 설치 후
**새 터미널**을 열어야 서버가 인식합니다.

## 서버 실행

```powershell
# 기본: streamable-http, 127.0.0.1:8000
powershell -ExecutionPolicy Bypass -File scripts\3-run_server.ps1

# 직접 실행도 가능
uv run server.py
```

설정은 `config.yaml`(선택, git 제외)의 `server` 섹션으로 제어합니다. 예시는
[config.yaml.example](config.yaml.example) 참고. 우선순위는 **CLI 인자 > 환경변수 > config.yaml**.

```yaml
device:
  name: null            # 단일 기기면 자동 선택, 다중이면 시리얼 지정
server:
  transport: "streamable-http"   # "stdio" / "sse" 도 지원
  host: "127.0.0.1"     # 사내망 공유 시 0.0.0.0 (+ auth_token 필수)
  port: 8000
  auth_token: ""        # 설정 시 "Authorization: Bearer <token>" 요구
```

> `3-run_server.ps1`은 사용자 환경변수(`JAVA_HOME`/`JADX_PATH`/`APKTOOL_PATH`/`ADB_PATH`)를
> 세션에 자동 로드하므로, 설치 직후 **새 터미널을 따로 열 필요가 없습니다**.

## Claude Desktop 연결

**자동(권장):** `claude_desktop_config.json`을 자동 탐색(MSIX 가상화 경로 포함)해
`Android Local MCP` 항목을 안전하게 병합합니다 (기존 설정·preferences 보존, 백업 생성):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\2-register_claude_desktop.ps1
# 미리보기: -DryRun, 모든 위치 갱신: -All, 포트 변경: -Port 8123
```

**수동:** Claude Desktop은 로컬에서 동작해 `127.0.0.1`에 직접 접속할 수 있습니다.
`mcp-remote` 브리지로 등록합니다 (실제 HTTP 서버는 독립 실행되어 Frida 세션이 유지됨):

```json
{
  "mcpServers": {
    "Android Local MCP": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:8000/mcp"]
    }
  }
}
```

설정 파일 위치 — **Microsoft Store(MSIX) 버전** Claude Desktop은 `%APPDATA%\Claude`가
아니라 패키지 가상화 경로에서 읽습니다:

```
%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json
```

편집 후 트레이 아이콘 → **종료(Quit)**로 완전히 끈 뒤 재실행하세요. (창만 닫으면
설정이 다시 로드되지 않습니다.) 자세한 내용은 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

> claude.ai **웹 조직 커넥터는 localhost를 사용할 수 없습니다**(Anthropic 클라우드가
> 접속하는 방식). 로컬 기기 분석에는 위의 Claude Desktop 방식을 사용하세요.

## 사용 예시 워크플로우

**앱 UI 자동화**
```
1. get_screenshot                              # 현재 화면 확인
2. get_uilayout                                # 클릭 가능 요소·좌표
3. execute_adb_shell_command("input tap X Y")  # 버튼 탭
4. get_screenshot                              # 결과 확인
```

**정적 분석 (androguard — 빠른 개요)**
```
1. analyze_manifest("com.example.app")   # 권한·exported 컴포넌트·보안 플래그
2. apk_info("com.example.app")           # 서명 인증서·해시
3. scan_secrets("com.example.app")       # 하드코딩 키·URL·IP
```

**정적 분석 (JADX — 코드 정독)**
```
1. jadx_decompile("com.example.app")
2. jadx_search_code("com.example.app", "password|secret|http")
3. jadx_read_source("com.example.app", "com/example/app/LoginActivity.java")
```

**네트워크 트래픽 캡처 (mitmproxy)**
```
1. network_start_capture(8080)   # 프록시 기동 + 기기 프록시 설정
   # (HTTPS는 기기에 mitmproxy CA 신뢰 필요 — http://mitm.it)
2. (앱에서 통신 발생)
3. network_list_flows(50)        # 캡처된 요청/응답 조회
4. network_stop_capture()
```

> Frida 준비: `scripts\1-setup_frida_server.ps1`가 연결된 기기의 ABI/root를 확인하고,
> 호스트 frida와 기기 frida-server 버전을 비교해 맞는 빌드를 push합니다(루팅 기기는 `-Start`로 기동).
> 이후 `frida_check_compatibility`로 일치를 확인하세요.

**동적 계측 (Frida, 루팅 기기/에뮬레이터)**
```
1. frida_spawn("com.example.app")                         # session_id (suspended)
2. frida_run_script(session_id, "<send()를 호출하는 JS>")   # 주입 + resume
3. frida_read_messages(session_id)                        # 후킹 출력 폴링
4. frida_detach(session_id)
```

## 단말 전제조건

- **USB 디버깅 승인**: 기기가 `unauthorized`면 모든 ADB 도구가 막힙니다. 기기 화면의
  "USB 디버깅 허용" 대화상자에서 "이 컴퓨터에서 항상 허용" 체크 후 승인하세요.
  (`adb kill-server && adb start-server && adb devices`로 대화상자 재유도)
- **Frida = root 필요**: `frida_*` 도구는 기기에 frida-server가 root로 떠 있어야
  동작합니다. **미루팅 단말에서는 사용 불가**이며, 루팅 기기 또는 Google APIs 안드로이드
  에뮬레이터(`adb root` 지원)를 사용하세요.

## 배포 모델 (권장)

- **분석가 개인 PC**에 설치, 단말을 그 PC에 연결, `127.0.0.1` 바인딩
- 같은 PC의 Claude Desktop이 `mcp-remote`로 접속
- 네트워크 노출·인증서 불필요, 기기가 분석가별로 격리됨
- ⚠️ 현재 서버는 모든 클라이언트가 **기기 1대를 공유**합니다. 다수 분석가·다수 기기
  중앙 운영에는 기기별 인스턴스 분리(포트 + `device.name`)가 필요합니다.

## 라이선스 / 출처

- 원본: [minhalvp/android-mcp-server](https://github.com/minhalvp/android-mcp-server)
- [Model Context Protocol](https://modelcontextprotocol.io/) 기반

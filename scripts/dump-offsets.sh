#!/usr/bin/env bash
# =============================================================================
#  dump-offsets.sh — anonymous.exe offset re-mapping dumper
# -----------------------------------------------------------------------------
#  libMyGame.so 가 업데이트될 때마다 src/offsets.ts 를 다시 매핑하기 위한
#  "정보 수집" 스크립트. 이 스크립트는 .so 를 읽기만 하고 아무것도 수정하지
#  않는다. 결과 txt 를 그대로 Claude 에게 주면 offsets.ts 를 갱신할 수 있다.
#
#  사용법:
#    bash dump-offsets.sh [libMyGame.so 경로] [옵션]
#
#      -o FILE        출력 파일 (기본: offsets-dump-<날짜>.txt)
#      --slim         [6] 클래스 심볼 인덱스 생략 (파일 크기 축소)
#      --no-disasm    디스어셈블 생략 (원시 워드 덤프만)
#      --deep         [5] UserInfor 접근자 디스어셈블 범위 확대
#      -h, --help     도움말
#
#  경로를 안 주면 현재 디렉터리 이하에서 libMyGame.so / libmygame.so 를 찾는다.
#
#  필요 도구: nm(또는 llvm-nm), od  ← 대부분의 리눅스/코드스페이스에 기본 탑재
#  선택 도구: llvm-objdump (arm64 디스어셈블), c++filt (심볼 디맹글)
#    없으면:  sudo apt-get install -y binutils llvm
# =============================================================================
set -uo pipefail

VERSION=1
OUT=""
SLIM=0
NO_DISASM=0
DEEP=0
LIB=""

while [ $# -gt 0 ]; do
    case "$1" in
        -o)          OUT="${2:-}"; shift 2 ;;
        --slim)      SLIM=1; shift ;;
        --no-disasm) NO_DISASM=1; shift ;;
        --deep)      DEEP=1; shift ;;
        -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
        -*)          echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
        *)           LIB="$1"; shift ;;
    esac
done

die() { echo "[!] $*" >&2; exit 1; }
log() { echo "[*] $*" >&2; }

# ----------------------------------------------------------------------------
# 대상 .so 찾기
# ----------------------------------------------------------------------------
if [ -z "$LIB" ]; then
    for c in ./libMyGame.so ./libmygame.so; do
        [ -f "$c" ] && LIB="$c" && break
    done
fi
if [ -z "$LIB" ]; then
    LIB=$(find . -maxdepth 6 -type f \( -iname 'libmygame.so' \) 2>/dev/null | head -1)
fi
[ -n "$LIB" ] || die "libMyGame.so 를 찾지 못했습니다. 경로를 인자로 주세요: bash $0 /path/to/libMyGame.so"
[ -f "$LIB" ] || die "파일 없음: $LIB"
LIB=$(cd "$(dirname "$LIB")" && pwd)/$(basename "$LIB")

[ -n "$OUT" ] || OUT="offsets-dump-$(date +%Y%m%d-%H%M%S).txt"

T=$(mktemp -d) || die "임시 디렉터리 생성 실패"
trap 'rm -rf "$T"' EXIT

# ----------------------------------------------------------------------------
# 도구 탐지
# ----------------------------------------------------------------------------
NM=""
for c in llvm-nm nm llvm-nm-18 llvm-nm-17 llvm-nm-16 llvm-nm-15 llvm-nm-14; do
    command -v "$c" >/dev/null 2>&1 && NM=$c && break
done
[ -n "$NM" ] || die "nm / llvm-nm 이 없습니다.  sudo apt-get install -y binutils llvm"
command -v od >/dev/null 2>&1 || die "od 가 없습니다 (coreutils)."

CXXFILT=""
command -v c++filt >/dev/null 2>&1 && CXXFILT="c++filt"
command -v llvm-cxxfilt >/dev/null 2>&1 && CXXFILT="llvm-cxxfilt"

# ----------------------------------------------------------------------------
# ELF 헤더 파싱 (readelf 없이 od 만으로 — 32/64비트 모두 지원)
# ----------------------------------------------------------------------------
u() { od -An -v -t "u$2" -j "$1" -N "$2" "$LIB" 2>/dev/null | tr -d ' \n'; }

MAGIC=$(od -An -v -t x1 -j 0 -N 4 "$LIB" | tr -d ' \n')
[ "$MAGIC" = "7f454c46" ] || die "ELF 파일이 아닙니다: $LIB"
EI_CLASS=$(u 4 1)
EI_DATA=$(u 5 1)
[ "$EI_DATA" = "1" ] || die "빅엔디안 ELF 는 지원하지 않습니다."
E_MACHINE=$(u 18 2)
case "$E_MACHINE" in
    183) ARCH="aarch64 (arm64-v8a)"; FIXED4=1 ;;
    40)  ARCH="arm (armeabi-v7a)";   FIXED4=0 ;;
    62)  ARCH="x86-64";              FIXED4=0 ;;
    3)   ARCH="i386";                FIXED4=0 ;;
    *)   ARCH="unknown(e_machine=$E_MACHINE)"; FIXED4=0 ;;
esac

if [ "$EI_CLASS" = "2" ]; then
    ELFBITS=64
    PHOFF=$(u 32 8); PHENTSIZE=$(u 54 2); PHNUM=$(u 56 2)
    PT_OFF_O=8;  PT_OFF_S=8
    PT_VAD_O=16; PT_VAD_S=8
    PT_FSZ_O=32; PT_FSZ_S=8
else
    ELFBITS=32
    PHOFF=$(u 28 4); PHENTSIZE=$(u 42 2); PHNUM=$(u 44 2)
    PT_OFF_O=4;  PT_OFF_S=4
    PT_VAD_O=8;  PT_VAD_S=4
    PT_FSZ_O=16; PT_FSZ_S=4
fi

# PT_LOAD 세그먼트 수집: "vaddr filesz fileoff"
: > "$T/loads.txt"
i=0
while [ "$i" -lt "${PHNUM:-0}" ]; do
    base=$(( PHOFF + i * PHENTSIZE ))
    ptype=$(u "$base" 4)
    if [ "$ptype" = "1" ]; then   # PT_LOAD
        po=$(u $(( base + PT_OFF_O )) $PT_OFF_S)
        pv=$(u $(( base + PT_VAD_O )) $PT_VAD_S)
        pf=$(u $(( base + PT_FSZ_O )) $PT_FSZ_S)
        echo "$pv $pf $po" >> "$T/loads.txt"
    fi
    i=$(( i + 1 ))
done

# vaddr -> 파일 오프셋 (없으면 빈 문자열)
v2o() {
    local v="$1" pv pf po
    while read -r pv pf po; do
        if [ "$v" -ge "$pv" ] && [ "$v" -lt $(( pv + pf )) ]; then
            echo $(( v - pv + po )); return 0
        fi
    done < "$T/loads.txt"
    echo ""
}

# ----------------------------------------------------------------------------
# 심볼 테이블 수집  ->  $T/syms.txt : "name<TAB>vaddr_dec<TAB>size_dec<TAB>type"
# ----------------------------------------------------------------------------
log "심볼 테이블 읽는 중 ..."
: > "$T/nm.raw"
"$NM" -D -S --defined-only "$LIB" >> "$T/nm.raw" 2>/dev/null
"$NM"    -S --defined-only "$LIB" >> "$T/nm.raw" 2>/dev/null

awk '
    { a=$1
      if (a !~ /^[0-9a-fA-F]+$/) next
      if (NF >= 4 && $2 ~ /^[0-9a-fA-F]+$/) { sz=$2; ty=$3; nm=$4 }
      else if (NF >= 3)                     { sz="";  ty=$2; nm=$3 }
      else next
      if (nm == "") next
      print nm "\t" a "\t" sz "\t" ty
    }
' "$T/nm.raw" | sort -u > "$T/syms.hex"

# 16진 -> 10진 변환 (awk strtonum 은 mawk 에 없으므로 bash 로 처리하지 않고
# printf 로 일괄 변환)
hex2dec_file() {
    awk -F'\t' '{ printf "%s\t%s\t%s\t%s\n", $1, $2, ($3==""?"0":$3), $4 }' "$1"
}
hex2dec_file "$T/syms.hex" > "$T/syms.txt"

SYMCOUNT=$(wc -l < "$T/syms.txt" | tr -d ' ')
[ "$SYMCOUNT" -gt 0 ] || die "심볼을 하나도 읽지 못했습니다 (완전 스트립된 .so?)."

# name -> "hexaddr hexsize type"
declare -A SYMADDR SYMSIZE SYMTYPE
while IFS=$'\t' read -r nm a sz ty; do
    SYMADDR["$nm"]="$a"; SYMSIZE["$nm"]="$sz"; SYMTYPE["$nm"]="$ty"
done < "$T/syms.txt"

hx() { printf '%s' "$1" | tr 'a-f' 'A-F'; }
dec() { echo $(( 16#$1 )); }

# ----------------------------------------------------------------------------
# 디스어셈블러 탐지
# ----------------------------------------------------------------------------
DISASM=""
if [ "$NO_DISASM" -eq 0 ]; then
    TESTADDR=$(awk -F'\t' '$4=="T" || $4=="t" {print $2; exit}' "$T/syms.txt")
    if [ -n "$TESTADDR" ]; then
        ta=$(( 16#$TESTADDR ))
        for c in llvm-objdump llvm-objdump-18 llvm-objdump-17 llvm-objdump-16 \
                 llvm-objdump-15 llvm-objdump-14 objdump; do
            command -v "$c" >/dev/null 2>&1 || continue
            if "$c" -d --start-address=$ta --stop-address=$((ta+16)) "$LIB" 2>/dev/null \
                 | grep -qE '^[[:space:]]*[0-9a-f]+:'; then
                DISASM="$c"; break
            fi
        done
    fi
fi

# ----------------------------------------------------------------------------
# 출력 헬퍼
# ----------------------------------------------------------------------------
exec 3>"$OUT"
o()  { printf '%s\n' "$*" >&3; }
sec(){ o ""; o "==============================================================================="; o "$*"; o "==============================================================================="; }

# 파일 오프셋 FOFF 에서 LEN 바이트를 4바이트 워드로 덤프 -> "hex<TAB>dec" 목록
words() {
    local foff="$1" len="$2"
    od -An -v -t x4 -j "$foff" -N "$len" "$LIB" 2>/dev/null \
        | tr -s ' ' '\n' | sed '/^$/d' | tr 'a-f' 'A-F' > "$T/w.hex"
    od -An -v -t d4 -j "$foff" -N "$len" "$LIB" 2>/dev/null \
        | tr -s ' ' '\n' | sed '/^$/d' > "$T/w.dec"
    paste "$T/w.hex" "$T/w.dec"
}

# 망글링된 이름에서 구성요소(클래스/메서드) 추출
components() {
    local s="$1"
    s="${s#_Z}"; s="${s#N}"; s="${s#K}"; s="${s#N}"
    local len rest
    while [[ "$s" =~ ^([0-9]+)(.*)$ ]]; do
        len="${BASH_REMATCH[1]}"; rest="${BASH_REMATCH[2]}"
        printf '%s\n' "${rest:0:len}"
        s="${rest:len}"
    done
}

demangle_one() {
    if [ -n "$CXXFILT" ]; then printf '%s' "$1" | $CXXFILT; else printf '%s' "$1"; fi
}

# 심볼이 사라졌을 때 후보 찾기
candidates() {
    local mangled="$1" cls meth
    mapfile -t _c < <(components "$mangled")
    local n=${#_c[@]}
    [ "$n" -ge 1 ] || return 0
    meth="${_c[$((n-1))]}"
    cls="${_c[0]}"
    awk -F'\t' -v c="$cls" -v m="$meth" \
        'index($1,c)>0 && index($1,m)>0 {print $2"\t"$1}' "$T/syms.txt" | head -12
    # 메서드 이름만으로도 한 번 더 (클래스가 바뀐 경우)
    awk -F'\t' -v c="$cls" -v m="$meth" \
        'index($1,m)>0 && index($1,c)==0 {print $2"\t"$1}' "$T/syms.txt" | head -6
}

# 함수 디스어셈블: $1=vaddr(dec) $2=len(bytes) $3=출력 prefix
disasm_func() {
    local va="$1" len="$2"
    [ -n "$DISASM" ] || return 1
    "$DISASM" -d --start-address=$va --stop-address=$(( va + len )) "$LIB" 2>/dev/null \
      | grep -E '^[[:space:]]*[0-9a-f]+:' \
      | awk -v fixed="$FIXED4" '
          { line=$0
            sub(/^[[:space:]]*[0-9a-f]+:[[:space:]]*/, "", line)
            gsub(/\t/, " ", line)
            if (fixed==1) printf "    +0x%03X  %s\n", (NR-1)*4, line
            else          printf "    %s\n", $0
          }'
}

# >>> BEGIN GENERATED TABLES (node scripts/gen-dump-tables.cjs 로 재생성)
# ----------------------------------------------------------------------------
#  임베드된 테이블 — src/offsets.ts 에서 생성됨
#  (offsets.ts 가 바뀌면 node scripts/gen-dump-tables.cjs 로 다시 생성하세요)
# ----------------------------------------------------------------------------

# key|mangled
SYM_TABLE=$(cat <<'EOF'
buy.buyWithGold|_ZN16SystemPacketSend11BuyWithGoldEh
buy.buyCharacter|_ZN16SystemPacketSend12BuyCharacterEh
buy.buyBoost|_ZN16SystemPacketSend8BuyBoostEh
buy.buyWithClanGold|_ZN16SystemPacketSend15BuyWithClanGoldEh
buy.buyResetKillDeathRatio|_ZN16SystemPacketSend22BuyResetKillDeathRatioEh
buy.buyItem|_ZN16SystemPacketSend7BuyItemEhhth
buy.buyRandomOption|_ZN16SystemPacketSend15BuyRandomOptionEhhhh
buy.buyToyItem|_ZN16SystemPacketSend10BuyToyItemEjhi
buy.equip|_ZN16SystemPacketSend5EquipEhhh
buy.equipShort|_ZN16SystemPacketSend5EquipEhht
buy.getRewardClassPackage|_ZN16SystemPacketSend12ClassPackage23GetRewardInClassPackageEhhmhhhh
ingame.hitUser|_ZN16SystemPacketSend7HitUserERK9UserInforhS2_RKN7cocos2d4Vec3Esf
ingame.electricDebuffToUser|_ZN9GameScene25ElectricDebuffToUserSkillER9UserInforR5CBuff
ingame.buffHitElectric|_ZN16SystemPacketSend15BuffHitElectricERK9UserInforjj
ingame.buffHitElectricAi|_ZN16SystemPacketSend21BuffHitElectricAIUserERK9UserInforjj
ingame.buffHitElectricOff|_ZN19SystemOfflinePacket15BuffHitElectricERK9UserInforjj
ingame.debuffSkillMagoTotem|_ZN16SystemPacketSend20DeBuffSkillMagoTotemEjj
ingame.updateHookSkill|_ZN9GameScene15UpdateHookSkillEP9UserInfor
ingame.updateMedicSkill|_ZN9GameScene16UpdateMedicSkillEP9UserInfor
ingame.ironSetActivation|_ZN5Skill4Iron13SetActivationER9UserInforb
ingame.setEnableJump|_ZN5Cloud8CharData13SetEnableJumpEb
ingame.medicSelfHeal|_ZN19SystemOfflinePacket20ProcessMedicSelfHealERK9UserInfor
ingame.buffOnWheelleg|_ZN16SystemPacketSend14BuffOnWheellegERK9UserInfor
ingame.buffMagoTotem|_ZN16SystemPacketSend18BuffSkillMagoTotemEjRKSt4listIjSaIjEE
ingame.timeOverRespawn|_ZN16SystemPacketSend22TimeOverRespawnWaitingERK9UserInfor
ingame.changeMissionCount|_ZN16SystemPacketSend22SendChangeMissionCountEjmjt
ingame.completeGameData|_ZN16SystemPacketSend20SendCompleteGameDataEi
ingame.MoveAi|_ZN14UserMoveSystem6MoveAIERNS_13CollisionDataERN7cocos2d4Vec3ES4_fR9GameSceneR9UserInforf
ingame.getMySkillCoolTime|_ZN5Skill18GetMySkillCoolTimeEv
ingame.getMaxSkill|_ZN5Skill16GetMaxSkillCountEh
ingame.getCurSkill|_ZN5Skill16GetCurSkillCountEv
ingame.makeSkillAvailable|_ZN9GameScene18MakeSkillAvailableEv
ingame.getSkillInvokeTime|_ZN20CharStatusCalculator18GetSkillInvokeTimeEh
ingame.skillOff|_ZN16SystemPacketSend8SkillOffERK9UserInfor
ingame.isSkillManyTimes|_ZN5Skill16IsSkillManyTimesEh
ingame.calculateSpeed|_ZN14UserMoveSystem14CalculateSpeedERfR9GameSceneR9UserInforf
ingame.createMoveSpeed|_ZN16SystemPacketSend19CreateMoveSpeedBuffEjj
ingame.createMaxBarrier|_ZN16SystemPacketSend20CreateMaxBarrierBuffEjj
ingame.createDamageReduction|_ZN16SystemPacketSend25CreateDamagereductionBuffERK9UserInfor
ingame.barrierRecharge|_ZN16SystemPacketSend15BarrierRechargeERK9UserInfor
ingame.createChooChoo|_ZN16SystemPacketSend18CreateChooChooBuffERK9UserInfor
ingame.getRespawnTime|_ZNK9GameScene14GetRespawnTimeEv
ingame.wheellegSpeedUpBuffApplyBuff|_ZN20CWheellegSpeedUpBuff9ApplyBuffEP9UserInfor
ingame.checkRemainedBullet|_ZN10UtilWeapon19CheckRemainedBulletERK9UserInfor
ingame.getMedal|_ZN9GameScene8GetMedalEh
ingame.canHeal|_ZN9GameScene7CanHealEP9UserInforS1_
ingame.gameSceneInit|_ZN9GameScene4initEv
charStatus.getMaxHP|_ZN20CharStatusCalculator8GetMaxHPERK9UserInforh
charStatus.getMaxBarrier|_ZN20CharStatusCalculator13GetMaxBarrierERK9UserInfor
charStatus.getShootDelay|_ZN20CharStatusCalculator13GetShootDelayERK9UserInfor
charStatus.getReloadSpeed|_ZN20CharStatusCalculator18GetReloadSpeedRateERK9UserInfor
charStatus.getMoveSpeed|_ZN20CharStatusCalculator12GetMoveSpeedER9UserInfor
charStatus.getSkillDamage|_ZN20CharStatusCalculator14GetSkillDamageERK9UserInfor
charStatus.getSkillCooltime|_ZN20CharStatusCalculator16GetSkillCoolTimeERK9UserInfor
charStatus.getShotgunBullet|_ZN20CharStatusCalculator16GetShotGunBulletERK9UserInfor
charStatus.getBodyshotDamage|_ZN20CharStatusCalculator21GetBodyShotDamageRateERK9UserInfor
charStatus.getHeadshotDamage|_ZN20CharStatusCalculator21GetHeadShotDamageRateERK9UserInfor
charStatus.cookerBuffWeight|_ZN20CharStatusCalculator19GetCookerBuffWeightERK9UserInfor
charRef.getJumpSpeed|_ZNK13CCharacterRef12GetJumpSpeedEh
charRef.getMoveSpeed|_ZNK13CCharacterRef12GetMoveSpeedEh
charRef.getMaxBarrier|_ZNK13CCharacterRef13GetMaxBarrierEh
charRef.getSkillDamage|_ZNK13CCharacterRef14GetSkillDamageEh
charRef.getSkillCooltime|_ZNK13CCharacterRef16GetSkillCoolTimeEh
charRef.getBarrierRecovery|_ZNK13CCharacterRef18GetBarrierRecoveryEh
clan.matchEndGame|_ZN16SystemPacketSend16ClanMatchEndGameEjhj
clan.matchStartReq|_ZN16SystemPacketSend21ClanMatchStartRequestEv
clan.matchReqReady|_ZN16SystemPacketSend17ClanMatchReqReadyEv
clan.matchCreateTeam|_ZN16SystemPacketSend19ClanMatchCreateTeamEv
clan.reqInfoEndMatch|_ZN16SystemPacketSend30ClanRequestInformationEndMatchEj
clan.clanBreakup|_ZN16SystemPacketSend11ClanBreakupEv
clan.clanCreate|_ZN16SystemPacketSend10ClanCreateERKSsS1_hh
clan.clanLeave|_ZN16SystemPacketSend9ClanLeaveEv
clan.clanAccept|_ZN16SystemPacketSend27ClanAcceptWaitingUserToJoinEjj
clan.clanInvite|_ZN16SystemPacketSend14ClanInviteUserEj
clan.clanChangeMemberGrade|_ZN16SystemPacketSend21ClanChangeMemberGradeEjh
clan.clanChangeIntroduceMessage|_ZN16SystemPacketSend26ClanChangeIntroduceMessageEjPKc
clan.clanRequestInformation|_ZN16SystemPacketSend22ClanRequestInformationEj
clan.clanKickMember|_ZN16SystemPacketSend14ClanKickMemberEj
cloud.getSkillTime|_ZN5Cloud8CharData12GetSkillTimeEv
cloud.getSkillElapsed|_ZN5Cloud8CharData19GetSkillElapsedTimeEv
cloud.isSkillAvailable|_ZN5Cloud8CharData16IsSkillAvailableEv
cloud.getSendContribPacketTime|_ZN5Cloud8GameData24GetSendContribPacketTimeEv
cloud.setSendContribPacketTime|_ZN5Cloud8GameData24SetSendContribPacketTimeEf
cloud.getIsVisibleSnail|_ZN5Cloud8GameData17GetIsVisibleSnailEv
cloud.setIsVisibleSnail|_ZN5Cloud8GameData17SetIsVisibleSnailEb
cloud.getAbusingDetector|_ZN5Cloud7NetData18GetAbusingDetectorEv
cloud.getIsTest|_ZN5Cloud8GameData9GetIsTestEv
cloud.getIsTutorial|_ZN5Cloud8GameData13GetIsTutorialEv
global.updatePacketReceiveTime|_ZN16SystemPacketSend23UpdatePacketReceiveTimeEf
global.requestLogin|_ZN16SystemPacketSend12RequestLoginEiRKSsS1_
global.onReceive|_ZN10LobbyScene9OnReceiveEiPKci
global.testDeleteAccount|_ZN16SystemPacketSend17TestDeleteAccountEv
global.deleteAccount|_ZN16SystemPacketSend20RequestDeleteAccountEv
global.chatting|_ZN16SystemPacketSend8ChattingEhOSs
global.getUserByOrder|_ZN15UserInfoManager14GetUserByOrderEh
global.getUserByUserSeq|_ZN15UserInfoManager16GetUserByUserSeqEj
global.resetPacketReceive|_ZN16SystemPacketSend22ResetPacketReceiveTimeEv
global.sendPacket|_ZN16SystemPacketSend10SendPacketEv
global.addPacketData|_ZN16SystemPacketSend13AddPacketDataIhEEvRKT_
global.getTCPSocketManager|_ZN5Cloud7NetData19GetTCPSocketManagerEv
global.changeNickname|_ZN16SystemPacketSend14ChangeNicknameEhPKch
global.connectToGameServer|_ZN19SystemPacketReceive19ConnectToGameServerEv
global.setPSAuthCode|_ZN19SystemPacketReceive13SetPSAuthCodeEv
global.toggleAbuseDetector|_ZN9GameScene21ToggleAbusingDetectorEb
global.abuseDetectorOnSkill|_ZN15AbusingDetector10OnUseSkillERK14InGameNotiInfo
global.sendPurchasePass|_ZN16SystemPacketSend16SendPurchasePassEjh
global.sendPurchasePassTier|_ZN16SystemPacketSend20SendPurchasePassTierEjh
global.purchaseHeroPackage|_ZN12UtilPurchase19PurchaseHeroPackageEih
global.receiveReward|_ZN12UIMilChoPass13ReceiveRewardEh
global.sendReqPassReward|_ZN16SystemPacketSend17SendReqPassRewardEjjhhh
global.sendReqUserPassData|_ZN16SystemPacketSend19SendReqUserPassDataEj
global.sendKnockBack|_ZN16SystemPacketSend13SendKnockBackEjN7cocos2d4Vec3E
global.changeTeam|_ZN16SystemPacketSend10ChangeTeamEv
global.reportClanMark|_ZN16SystemPacketSend14ReportClanMarkEjj
global.reportHackingUser|_ZN16SystemPacketSend17ReportHackingUserEjjh
global.sendReqDailyBonus|_ZN16SystemPacketSend17SendReqDailyBonusEh
fmatch.kickUserSlot|_ZN16SystemPacketSend18FMatchKickUserSlotEh
camera.getCamera|_ZN5Cloud10CameraData9GetCameraEv
camera.getCameraAngleX|_ZN5Cloud10CameraData15GetCameraAngleXEv
camera.setCameraAngleX|_ZN5Cloud10CameraData15SetCameraAngleXEf
camera.getCameraAngleY|_ZN5Cloud10CameraData15GetCameraAngleYEv
camera.setCameraAngleY|_ZN5Cloud10CameraData15SetCameraAngleYEf
camera.getCameraZoom|_ZN5Cloud10CameraData13GetCameraZoomEv
camera.setCameraZoom|_ZN5Cloud10CameraData13SetCameraZoomEf
camera.getCameraDistanceZ|_ZN5Cloud10CameraData18GetCameraDistanceZEv
camera.getCameraDistanceY|_ZN5Cloud10CameraData18GetCameraDistanceYEv
camera.getCameraRay|_ZN5Cloud10CameraData12GetCameraRayEv
camera.setCameraRayOrigin|_ZN5Cloud10CameraData18SetCameraRayOriginERKN7cocos2d4Vec3E
camera.getCameraUser|_ZN5Cloud10CameraData24GetCameraUserInformationEv
call.changeGun|_ZN9GameScene13CallChangeGunEh
call.gameChangeGun|_ZN9GameScene12ChangeWeaponEP9UserInfor
call.touchGunEvent|_ZN9GameScene13touchGunEventEPN7cocos2d3RefENS0_2ui6Widget14TouchEventTypeEh
call.throw|_ZN9GameScene9CallThrowEv
call.jump|_ZN9GameScene8CallJumpEv
call.skill|_ZN9GameScene9CallSkillEv
call.zoom|_ZN9GameScene8CallZoomEb
call.reload|_ZN9GameScene10CallReloadEv
call.shootStart|_ZN9GameScene14CallShootStartEv
call.shootEnd|_ZN9GameScene12CallShootEndEv
mapData.getMapType|_ZN5Cloud7MapData10GetMapTypeEv
mapData.getMode|_ZN5Cloud7MapData7GetModeEv
mapData.getRowCountSprite|_ZN5Cloud7MapData20GetMapRowCountSpriteEv
mapData.getVisibleCountSprite|_ZN5Cloud7MapData24GetMapVisibleCountSpriteEv
socket.connect|_ZN16TCPSocketManager7connectEP13SocketAddress
socket.disconnect|_ZN16TCPSocketManager10disconnectEi
socket.disconnectAll|_ZN16TCPSocketManager13disconnectAllEv
socket.setCodeKey|_ZN16TCPSocketManager10setCodeKeyEiPSsmRKSsS2_
assist.isAimAssist|_ZNK9GameScene11IsAimAssistEv
assist.AssistRequestInGameRoomUsers|_ZN16SystemPacketSend28AssistRequestInGameRoomUsersEv
assist.SendAimAssistOption|_ZN16SystemPacketSend19SendAimAssistOptionEb
ad.adsRequestShopADReward|_ZN16SystemPacketSend22AdsRequestShopADRewardEh
ad.onRewarded|_ZN8Paradiso9AdManager10OnRewardedEv
ad.isAvailableAds|_ZNK8Paradiso9AdManager14IsAvailableAdsEv
ad.isAvailableCount|_ZNK8Paradiso9AdManager16IsAvailableCountEv
ad.isAvailableTime|_ZNK8Paradiso9AdManager15IsAvailableTimeEv
ad.isAvailableInitCycle|_ZNK8Paradiso9AdManager20IsAvailableInitCycleEv
ad.isAvailableShopADCount|_ZNK8Paradiso9AdManager22IsAvailableShopADCountEh
ad.isAvailableShopADTime|_ZNK8Paradiso9AdManager21IsAvailableShopADTimeEh
ad.isAvailableShopADInitCycle|_ZNK8Paradiso9AdManager26IsAvailableShopADInitCycleEh
ad.isAvailableCountBattleRoyal|_ZNK8Paradiso9AdManager27IsAvailableCountBattleRoyalEv
ad.isAvailableTimeBattleRoyal|_ZNK8Paradiso9AdManager26IsAvailableTimeBattleRoyalEv
ad.isAvailableInitCycleBattleRoyal|_ZNK8Paradiso9AdManager31IsAvailableInitCycleBattleRoyalEv
EOF
)

# key|mangled|offset|offword|offdec|onword|ondec|type
XA_TABLE=$(cat <<'EOF'
no-recoil|_ZN6Recoil11ShakeCameraERKf|0x44|BD000420|-1124072416|1E281000|505942016|s32
no-clip|_ZN14UserMoveSystem6MoveAIERNS_13CollisionDataERN7cocos2d4Vec3ES4_fR9GameSceneR9UserInforf|-0x4|3C23D70A|0.01|42C80000|100|f32
no-spread1|_ZN20CharStatusCalculator18GetAimSpreadMovingERK9UserInfor|0x10|BD402400|-1119869952|1E281000|505942016|s32
no-spread2|_ZN20CharStatusCalculator20GetAimSpreadShootingERK9UserInfor|0x10|BD402000|-1119870976|1E281000|505942016|s32
no-spread-idle|_ZN6Spread19GetAimGapByCurStateEv|0x14C|BD401EA0|-1119871328|1E281000|505942016|s32
no-spread-idle-zoom|_ZN6Spread19GetAimGapByCurStateEv|0x144|BD402EA0|-1119867232|1E281000|505942016|s32
no-spread-jump|_ZN6Spread19GetAimGapByCurStateEv|0x104|BD402AA0|-1119868256|1E281000|505942016|s32
no-spread-jump-zoom|_ZN6Spread19GetAimGapByCurStateEv|0xDC|BD403AA0|-1119864160|1E281000|505942016|s32
no-spread-move-zoom|_ZN6Spread19GetAimGapByCurStateEv|0xFC|BD4036A0|-1119865184|1E281000|505942016|s32
no-spread-shoot-zoom|_ZN6Spread19GetAimGapByCurStateEv|0x124|BD4032A0|-1119866208|1E281000|505942016|s32
no-reload|_ZN20CharStatusCalculator18GetReloadSpeedRateERK9UserInfor|0x10|BC417000|-1136562176|1E27D000|505925632|s32
instant-respawn|_ZNK9GameScene14GetRespawnTimeEv|0x18|1E200820|505415712|1E200800|505415680|s32
body-one-kill|_ZN20CharStatusCalculator21GetBodyShotDamageRateERK9UserInfor|0x0|1E2E1000|506335232|1E27D000|505925632|s32
head-one-kill|_ZN20CharStatusCalculator21GetHeadShotDamageRateERK9UserInfor|0x10|BC40F000|-1136594944|1E27D000|505925632|s32
skill-damage|_ZNK13CCharacterRef14GetSkillDamageEh|0x60|B8469002|-1203335166|5280FA02|1384184322|s32
cooker-buff|_ZN20CharStatusCalculator19GetCookerBuffWeightERK9UserInfor|0x0|1E2E1000|506335232|1E27D000|505925632|s32
EOF
)

# key|value
AN_TABLE=$(cat <<'EOF'
camera-base|0x0
yaw|0x4
pitch|0x0
camX|0xC
camY|0x10
camZ|0x14
cam-distance|0x24
position-base|0x7ABE28
x|0x7ABE28
y|0x7ABE2C
z|0x7ABE30
cash-base|0x2D16FC
dia|0x2D16FC
dia-total|0x2D1704
dia-used|0x2D1708
gold|0x2D170C
gold-total|0x2D1710
gold-used|0x2D1714
clan-gold|0x2D1718
skill-base|0x8BF075
grenade-base|0x8BEFC9
EOF
)
# <<< END GENERATED TABLES

# ============================================================================
#  [0] 헤더
# ============================================================================
log "덤프 작성: $OUT"
o "### anonymous.exe OFFSET DUMP  (format v$VERSION)"
o "### 이 파일을 그대로 Claude 에게 주면 src/offsets.ts 를 갱신합니다."
o ""
o "generated   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
o "file        : $LIB"
o "size        : $(wc -c < "$LIB" | tr -d ' ') bytes"
o "md5         : $( (md5sum "$LIB" 2>/dev/null || md5 -q "$LIB" 2>/dev/null) | awk '{print $1}')"
o "sha1        : $( (sha1sum "$LIB" 2>/dev/null || shasum "$LIB" 2>/dev/null) | awk '{print $1}')"
o "elf         : ELF${ELFBITS} LE  machine=$ARCH"
o "symbols     : $SYMCOUNT (defined)"
o "nm          : $NM"
o "disassembler: ${DISASM:-<none — 원시 워드 덤프만 제공>}"
o "options     : slim=$SLIM no-disasm=$NO_DISASM deep=$DEEP"
o ""
o "PT_LOAD segments (vaddr / filesz / fileoff, decimal):"
while read -r pv pf po; do
    o "  vaddr=0x$(printf '%X' "$pv")  filesz=0x$(printf '%X' "$pf")  fileoff=0x$(printf '%X' "$po")"
done < "$T/loads.txt"

# ============================================================================
#  [1] SYMBOLS — src/offsets.ts 의 _symbols 테이블 전체
# ============================================================================
sec "[1] SYMBOLS  —  _symbols (src/offsets.ts §5)"
o "형식: SYM <key> | <status> | <vaddr> | <size> | <mangled>"
o "status: OK = 그대로 존재 / MISSING = 사라짐(시그니처 변경 등) → CAND 후보 참고"
o ""

SYM_OK=0; SYM_MISS=0
: > "$T/missing.txt"
while IFS='|' read -r key mangled; do
    [ -n "$key" ] || continue
    a="${SYMADDR[$mangled]:-}"
    if [ -n "$a" ]; then
        SYM_OK=$(( SYM_OK + 1 ))
        sz="${SYMSIZE[$mangled]:-0}"
        o "SYM $key | OK | $(printf '0x%X' $(( 16#$a ))) | $(printf '0x%X' $(( 16#${sz:-0} ))) | ${SYMTYPE[$mangled]:-?} | $mangled"
    else
        SYM_MISS=$(( SYM_MISS + 1 ))
        echo "$key|$mangled" >> "$T/missing.txt"
        o "SYM $key | MISSING | - | - | - | $mangled"
        o "    demangled: $(demangle_one "$mangled")"
        while IFS=$'\t' read -r ca cn; do
            [ -n "$ca" ] || continue
            o "    CAND $(printf '0x%X' $(( 16#$ca )))  $cn"
            o "         => $(demangle_one "$cn")"
        done < <(candidates "$mangled")
    fi
done <<< "$SYM_TABLE"
o ""
o "합계: OK=$SYM_OK  MISSING=$SYM_MISS"

# ============================================================================
#  [2] XA PATCH SITES — _xaOffset / _xaPatch
# ============================================================================
sec "[2] XA PATCH SITES  —  _xaOffset + _xaPatch (src/offsets.ts §1,§2)"
o "각 항목마다:"
o "  - 함수 주소/크기"
o "  - 기존 off 값(word)이 함수 안에서 발견되는 위치 => 새 offset 후보 (MATCH)"
o "  - 기존 offset 위치에 현재 들어있는 word (CURRENT)"
o "  - 함수 전체 디스어셈블/워드 덤프 (오프셋은 함수 시작 기준 +0x..)"
o ""

: > "$T/xa_summary.txt"
while IFS='|' read -r key mangled xoff offword offdec onword ondec ptype; do
    [ -n "$key" ] || continue
    o "-------------------------------------------------------------------------------"
    o "XA $key"
    o "  symbol      : $mangled"
    o "  demangled   : $(demangle_one "$mangled")"
    o "  old offset  : $xoff"
    o "  old off val : 0x$offword ($offdec, type=$ptype)"
    o "  on  val     : 0x$onword ($ondec)"
    a="${SYMADDR[$mangled]:-}"
    if [ -z "$a" ]; then
        o "  status      : SYMBOL MISSING  → [1] 섹션의 CAND 후보로 심볼부터 갱신 필요"
        echo "$key|SYMBOL-MISSING" >> "$T/xa_summary.txt"
        o ""
        continue
    fi
    va=$(( 16#$a ))
    sz=$(( 16#${SYMSIZE[$mangled]:-0} ))
    [ "$sz" -gt 0 ] || sz=512
    o "  status      : FOUND"
    o "  func vaddr  : 0x$(printf '%X' "$va")"
    o "  func size   : 0x$(printf '%X' "$sz")"

    # 덤프 범위: 함수 앞뒤 0x20 여유 (음수 offset 대응), 최대 0x800 바이트
    xo=$(( xoff ))
    lo=0; [ "$xo" -lt 0 ] && lo=$xo
    lo=$(( lo - 32 ))
    hi=$(( sz + 32 )); [ $(( xo + 4 )) -gt "$hi" ] && hi=$(( xo + 36 ))
    [ $(( hi - lo )) -gt 2048 ] && hi=$(( lo + 2048 ))
    lo=$(( (lo / 4) * 4 ))
    dstart=$(( va + lo ))
    dlen=$(( hi - lo ))
    foff=$(v2o "$dstart")
    if [ -z "$foff" ]; then
        o "  ! vaddr->file offset 변환 실패 (PT_LOAD 밖)"
        echo "$key|VADDR-UNMAPPED" >> "$T/xa_summary.txt"
        o ""
        continue
    fi

    words "$foff" "$dlen" > "$T/xa.words"

    cur=$(awk -F'\t' -v n=$(( (xo - lo) / 4 + 1 )) 'NR==n {print $1"\t"$2}' "$T/xa.words")
    curhex=$(printf '%s' "$cur" | cut -f1)
    curdec=$(printf '%s' "$cur" | cut -f2)
    o "  CURRENT     : old offset $xoff 위치의 word = 0x${curhex:-????????} (${curdec:-?})"
    if [ "0x${curhex:-0}" = "0x$offword" ]; then
        o "  VERDICT     : ★ 그대로 일치 — 이 offset 은 수정 불필요"
        echo "$key|SAME|$xoff" >> "$T/xa_summary.txt"
    else
        mlist=$(awk -F'\t' -v w="$offword" -v lo="$lo" '
            $1==w { off = lo + (NR-1)*4
                    if (off < 0) printf "%s-0x%X", (c++?", ":""), -off
                    else         printf "%s0x%X",  (c++?", ":""),  off }
            END { print "" }' "$T/xa.words")
        if [ -n "$mlist" ]; then
            o "  MATCH       : ★ 기존 off 값(0x$offword)이 다음 offset 에서 발견됨 → $mlist"
            echo "$key|MOVED|$mlist" >> "$T/xa_summary.txt"
        else
            o "  MATCH       : ✗ 기존 off 값(0x$offword)을 함수 안에서 찾지 못함"
            o "                → 상수 자체가 바뀌었을 가능성. 아래 덤프에서 수동 확인 필요."
            echo "$key|NOT-FOUND|-" >> "$T/xa_summary.txt"
        fi
        onlist=$(awk -F'\t' -v w="$onword" -v lo="$lo" '
            $1==w { off = lo + (NR-1)*4
                    if (off < 0) printf "%s-0x%X", (c++?", ":""), -off
                    else         printf "%s0x%X",  (c++?", ":""),  off }
            END { print "" }' "$T/xa.words")
        [ -n "$onlist" ] && o "  (참고) ON 값(0x$onword) 위치: $onlist  ← 이미 패치된 .so 일 수 있음"
    fi

    o "  --- 함수 덤프 (+offset 는 함수 시작 기준) ---"
    if [ -n "$DISASM" ] && [ "$FIXED4" -eq 1 ]; then
        disasm_func "$va" "$sz" | head -400 >&3
        if [ "$lo" -lt 0 ]; then
            o "  --- 함수 시작 이전 워드 (음수 offset 용) ---"
            awk -F'\t' -v lo="$lo" 'NR<=(-lo)/4 { off = lo + (NR-1)*4; printf "    -0x%03X  0x%s  %s\n", -off, $1, $2 }' "$T/xa.words" >&3
        fi
    else
        awk -F'\t' -v lo="$lo" '{ off = lo + (NR-1)*4
            if (off < 0) printf "    -0x%03X  0x%s  %s\n", -off, $1, $2
            else         printf "    +0x%03X  0x%s  %s\n",  off, $1, $2 }' "$T/xa.words" | head -400 >&3
    fi
    o ""
done <<< "$XA_TABLE"

# ============================================================================
#  [3] AN — 런타임 익명 메모리 오프셋 (자동 해석 불가)
# ============================================================================
sec "[3] AN OFFSETS  —  _anOffset (src/offsets.ts §3)  [수동/런타임]"
o "이 값들은 libMyGame.so 안의 주소가 아니라 게임 실행 중 익명(anonymous) 메모리"
o "영역 기준 오프셋이라서 .so 정적 분석으로는 확인할 수 없습니다."
o "현재 offsets.ts 에 들어있는 값을 그대로 기록하니, 게임 업데이트 후 인게임에서"
o "다시 스캔해 값이 바뀌었는지 확인해 주세요. (바뀐 게 없으면 그대로 두면 됩니다.)"
o ""
while IFS='|' read -r key val; do
    [ -n "$key" ] || continue
    o "AN $key = $val   [MANUAL]"
done <<< "$AN_TABLE"

# ============================================================================
#  [4] UserInfor(epos) 구조체 필드 — 참고용 접근자 디스어셈블
# ============================================================================
sec "[4] UserInfor(epos) 필드 확인용 접근자 디스어셈블 (src/offsets.ts §4 참고)"
o "_eposOffset 은 구조체 필드 오프셋이라 심볼로 직접 확인할 수 없습니다."
o "대신 UserInfor 를 인자로 받는 주요 함수들을 디스어셈블해 둡니다."
o "ldr/str 의 [x0, #0x..] 같은 즉시값으로 필드 위치가 바뀌었는지 대조할 수 있습니다."
o ""
ACCESSORS="_ZN20CharStatusCalculator8GetMaxHPERK9UserInforh
_ZN20CharStatusCalculator13GetMaxBarrierERK9UserInfor
_ZN20CharStatusCalculator12GetMoveSpeedER9UserInfor
_ZN20CharStatusCalculator13GetShootDelayERK9UserInfor
_ZN10UtilWeapon19CheckRemainedBulletERK9UserInfor
_ZN14UserMoveSystem14CalculateSpeedERfR9GameSceneR9UserInforf
_ZN9GameScene7CanHealEP9UserInforS1_
_ZN9GameScene15UpdateHookSkillEP9UserInfor
_ZN16SystemPacketSend7HitUserERK9UserInforhS2_RKN7cocos2d4Vec3Esf"
LIMIT=200; [ "$DEEP" -eq 1 ] && LIMIT=600
while read -r m; do
    [ -n "$m" ] || continue
    a="${SYMADDR[$m]:-}"
    o "-------------------------------------------------------------------------------"
    o "ACC $m"
    if [ -z "$a" ]; then o "    MISSING"; o ""; continue; fi
    va=$(( 16#$a )); sz=$(( 16#${SYMSIZE[$m]:-0} )); [ "$sz" -gt 0 ] || sz=512
    o "    vaddr=0x$(printf '%X' "$va")  size=0x$(printf '%X' "$sz")"
    if [ -n "$DISASM" ]; then
        disasm_func "$va" "$sz" | head -"$LIMIT" >&3
    else
        foff=$(v2o "$va")
        [ -n "$foff" ] && words "$foff" "$sz" | awk -F'\t' '{ printf "    +0x%03X  0x%s  %s\n", (NR-1)*4, $1, $2 }' | head -"$LIMIT" >&3
    fi
    o ""
done <<< "$ACCESSORS"

# ============================================================================
#  [5] 클래스별 심볼 인덱스 — 사라진 심볼의 새 시그니처 찾기용
# ============================================================================
if [ "$SLIM" -eq 0 ]; then
    sec "[5] CLASS SYMBOL INDEX  (관련 클래스의 모든 export 심볼)"
    o "MISSING 심볼의 새 시그니처를 찾을 때 사용합니다."
    o ""
    PREFIXES='16SystemPacketSend|19SystemPacketReceive|19SystemOfflinePacket|9GameScene|20CharStatusCalculator|13CCharacterRef|5Skill|5Cloud|6Spread|6Recoil|14UserMoveSystem|15UserInfoManager|15AbusingDetector|10UtilWeapon|12UtilPurchase|12UIMilChoPass|16TCPSocketManager|10LobbyScene|8Paradiso|5CBuff|20CWheellegSpeedUpBuff'
    awk -F'\t' -v pre="$PREFIXES" '
        BEGIN { n=split(pre, p, "|") }
        { for (i=1; i<=n; i++) if (index($1, p[i]) > 0) { print $2"\t"$3"\t"$1; break } }
    ' "$T/syms.txt" | sort > "$T/classidx.txt"
    o "총 $(wc -l < "$T/classidx.txt" | tr -d ' ') 개"
    o ""
    awk -F'\t' '{ a=$1; z=$2; sub(/^0+/, "", a); sub(/^0+/, "", z)
                       printf "IDX 0x%s | 0x%s | %s\n", (a==""?"0":toupper(a)), (z==""?"0":toupper(z)), $3 }' "$T/classidx.txt" >&3
fi

# ============================================================================
#  [6] 요약
# ============================================================================
sec "[6] SUMMARY"
o "symbols : OK=$SYM_OK  MISSING=$SYM_MISS"
if [ "$SYM_MISS" -gt 0 ]; then
    o ""
    o "MISSING 심볼 목록:"
    while IFS='|' read -r k m; do [ -n "$k" ] && o "  - $k  ($m)"; done < "$T/missing.txt"
fi
o ""
o "XA 패치 지점:"
while IFS='|' read -r k st extra; do
    [ -n "$k" ] || continue
    case "$st" in
        SAME)  o "  - $k : 변경 없음 (offset $extra 그대로)" ;;
        MOVED) o "  - $k : ★ offset 이동 → $extra" ;;
        *)     o "  - $k : ! $st $extra" ;;
    esac
done < "$T/xa_summary.txt"
o ""
o "AN / epos 오프셋은 인게임 확인 필요 (위 [3],[4] 참고)."
o ""
o "### END OF DUMP"

exec 3>&-

echo
echo "완료: $OUT  ($(wc -c < "$OUT" | tr -d ' ') bytes, $(wc -l < "$OUT" | tr -d ' ') lines)"
echo "심볼 OK=$SYM_OK MISSING=$SYM_MISS / 디스어셈블러=${DISASM:-none}"
echo "이 txt 파일을 그대로 Claude 에게 전달하세요."

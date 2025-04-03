PCMDIR="/mnt/sda4/pcm/build/bin"
TEST_EXEC="test_prog"
VIZIMAGE_PATH="./scripts/bandwidth.png"
VIZSCRIPT_PATH="./scripts/bandwidth.py"
ENTRY_DIGEST=8399588
KEY_DIGEST=8399652
VALUE_DIGEST=8399687
DUMMY_DIGEST_1=114514
DUMMY_DIGEST_2=1919810
DUMMY_DIGEST_3=618
REPEAT_TIMES=5

start_pcm() 
{
    config=$1
    rm ${config}_bw.csv
    $PCMDIR/pcm-memory 0.1 -csv="${config}_bw.csv" >/dev/null 2>&1 &
}

end_pcm() 
{
    pkill -9 -f pcm-memory >/dev/null 2>&1
}

# 5833531861877376	8399585	[0x4013a5,0x40173c]	16	459a00	1
# 5833531978524976	8399649	[0x4013e5,0x40173c]	8	757cf0	1
# 5833531978525176	8399684	[0x401408,0x40173c]	128	757d10	1

offload_exp() {
    local offload_list=$1
    local repeat=$2
    local sum=0

    > results.txt
    
    export OFFLOAD_CANDIDATES=${offload_list}
    for i in $(seq 1 "$repeat"); do
        make test 2>&1 >/dev/null
    done

    awk '!/hit count/ { sum += $1; count++ } END { if (count > 0) print "average:", sum / count; else print "failed to take average." }' results.txt
}


offload_exp ${DUMMY_DIGEST_1},${DUMMY_DIGEST_2},${DUMMY_DIGEST_3} ${REPEAT_TIMES}
offload_exp ${ENTRY_DIGEST},${DUMMY_DIGEST_1},${DUMMY_DIGEST_2} ${REPEAT_TIMES}
offload_exp ${KEY_DIGEST},${DUMMY_DIGEST_1},${DUMMY_DIGEST_2} ${REPEAT_TIMES}
offload_exp ${VALUE_DIGEST},${DUMMY_DIGEST_1},${DUMMY_DIGEST_2} ${REPEAT_TIMES}
offload_exp ${ENTRY_DIGEST},${KEY_DIGEST},${DUMMY_DIGEST_1} ${REPEAT_TIMES}
offload_exp ${ENTRY_DIGEST},${VALUE_DIGEST},${DUMMY_DIGEST_1} ${REPEAT_TIMES}
offload_exp ${KEY_DIGEST},${VALUE_DIGEST},${DUMMY_DIGEST_1} ${REPEAT_TIMES}
offload_exp ${ENTRY_DIGEST},${KEY_DIGEST},${VALUE_DIGEST} ${REPEAT_TIMES}
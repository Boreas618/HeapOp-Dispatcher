REDIS_RUN_DIR="/mnt/sda4/run/redis"

make clean
make ldlib.so MODE=PRERUN
mv ldlib.so ${REDIS_RUN_DIR}/prerun.so

make clean
make ldlib.so MODE=DEFAULT
mv ldlib.so ${REDIS_RUN_DIR}/offload.so

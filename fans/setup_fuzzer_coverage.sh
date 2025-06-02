#adb -s 710KPZK0476701 root
sleep 3
adb -s 710KPZK0476701 shell 'su root sh -c "setenforce 0"'
adb -s 710KPZK0476701 shell "su root sh -c 'rm -rf /data/local/tmp/fans-cov/'"
adb -s 710KPZK0476701 shell "su root sh -c 'mkdir -p /data/local/tmp/fans-cov/data && mkdir -p /data/local/tmp/fans-cov/tx_data_dump/ && chmod -R 777 /data/local/tmp/fans-cov/'"
adb -s 710KPZK0476701 push ./workdir/interface-model-extractor/model /data/local/tmp/fans-cov/
adb -s 710KPZK0476701 push ./seed/ /data/local/tmp/fans-cov
adb -s 710KPZK0476701 push ./native_service_fuzzer_coverage_debug /data/local/tmp/fans-cov
adb -s 710KPZK0476701 push ./fuzzer-engine/fuzzer-coverage/ /data/local/tmp/fans-cov
adb -s 710KPZK0476701 shell "su root sh -c 'killall native_service_fuzzer_coverage'"
# adb -s $1 shell "./data/fuzzer/native_service_fuzzer --log_level=info --interface=IDrm"
# adb -s $1 shell "./data/fuzzer/native_service_fuzzer --log_level=info --transaction=IDrm::13-13"

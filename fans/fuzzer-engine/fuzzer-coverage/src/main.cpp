#include <fuzzer/interface/interface.h>

#include <fuzzer/executor.h>
#include <fuzzer/generator.h>
#include <fuzzer/coverage.h>

#include <fuzzer/test.h>
#include <fuzzer/types/types.h>
#include <fuzzer/utils/java_vm.h>
#include <fuzzer/utils/log.h>
#include <fuzzer/utils/random.h>
#include <stdio.h>
#include <unistd.h>
#include <random>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

char *targetInterface = NULL;
char *targetTransaction = NULL;
char *seedPath = NULL;

// where do we execute the fuzzer
const char *fuzzer_dir = "/data/local/tmp/fans-cov/";
const char *seed_dir = "/data/local/tmp/fans-cov/data/";
const char *sha1_seeds = "/data/local/tmp/fans-cov/seed_sha1s.txt";

// coverage between frida-instrumented target and fuzzer
const int FRIDA_MAP_SIZE = 0x8000;
char const *shared_mem_path = "/data/local/tmp/tmpfs/.shmem";
// important filepaths used for sync between frida-instrumented target, fuzzer and orchestrator
char const *pid_path = "./.pid";
char const *pid_ack_path = "./.pid_ack";
char const *replay_done_path = "./.replay_done";
char const *do_interface_enum = "./.do_interface";
char const *do_interface_enum_ack = "./.do_interface_ack";
char const *do_interface_enum_done = "./.do_interface_done";
int wait_for_pid = 1;
int replay_seed = 0;
unsigned char* frida_shared_mem;
size_t timeout = 0x1000;

int __checkDeath(pid_t pid){
    int s = kill(pid, 0);
    if(s==-1){return 1;
    } else {return 0;}
}

pid_t get_service_pid(std::string service_name){
    char cmd[0x200];
    sprintf(cmd, "/data/local/tmp/dumpsys/dumpsys %s > /data/local/tmp/s_pid", service_name.c_str());
    printf("%s\n", cmd);
    system(cmd);
    FILE* file = fopen("/data/local/tmp/s_pid", "r");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }
    pid_t service_pid;
    if (fscanf(file, "%d", &service_pid) != 1) {
        fclose(file);
        return -1;  // Return -1 if fscanf fails to read an integer
    }
    fclose(file);
    return service_pid;
}

int get_random_int() {
    int random_value;
    int fd = open("/dev/urandom", O_RDONLY);  // Open /dev/urandom for reading
    if (fd == -1) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    // Read random data into random_value
    if (read(fd, &random_value, sizeof(random_value)) != sizeof(random_value)) {
        perror("Failed to read from /dev/urandom");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);  // Close the file descriptor
    return random_value;  // Return the random integer
}

void init(char *svcDir, char *structDir) {
  loadServiceInfo(svcDir, targetInterface, targetTransaction);
  loadStructureInfo(structDir);
  loadUnionInfo((char *)UNION_INFO_DIR);
  initEnumInfo((char *)ENUMERATION_INFO_DIR);
  loadFunctionInfo((char *)FUNCTION_INFO_DIR);

  initPackageNameList();
  initPermissionNameList();
  initMediaUrlList();

  initFDPool();
  initVarTypeMap();

  initCodecInfo();
  init_jvm(&vm, &env);
}

void dump_timeout(){
    // we don't care about the seed that generate the timeout we just want to retain the seed
    std::string out_path = std::string(fuzzer_dir) + std::string("/") + std::string("timeout-dummy");
    std::ofstream file(out_path, std::ios::out | std::ios::binary);
    file.write("timeout", strlen("timeout"));
    file.close();
}

void handle_alarm(int signum) {
    printf("TIMEOUT OCCURED!!");
    dump_timeout();
    _exit(0);
}

void startFuzzing() {
    initializeRng(get_random_int());
  FUZZER_LOGI("Start fuzzing...");
  Generator gen;
  Executor executor;
  status_t ret;
  pid_t service_pid = -1;
  unsigned long iteration=0;
  unsigned long new_seeds=0;
  // string stop = "Y";
  struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_alarm; // Set the signal handler
    sigaction(SIGALRM, &sa, NULL); // Register the handler
  while (true) {
    FUZZER_LOGI(
        "-------------------------------------------------------------------");
    printf("Fuzzer iteration %ld\n", iteration);
    Transaction tx = gen.generateTx();
    if(service_pid == -1){
        service_pid = get_service_pid(tx.serviceName);
        if(service_pid == -1){
            printf("Failed to get service pid????\n");
            exit(-1);
        }
    }
    printf("tx generated for pid: %d\n", service_pid);
    if(getenv("DUMPSHA1")){
        tx.dumpsha1(iteration);
    }
    alarm(timeout);
    ret = executor.run_cov(tx, frida_shared_mem, FRIDA_MAP_SIZE);
    alarm(0);
    //for(int i =0; i<10; i++){
    //    printf("rng: 0x%lx\n", rng());
    //}
    printf("executed transaction\n");
    if(__checkDeath(service_pid)){
        printf("SERVICE CRASHED!\n");
        tx.dump_crashed(fuzzer_dir, backup_rng);
        // exit the fuzzer after the service crashes to reset
        exit(0);
    }
    if(new_coverage(frida_shared_mem, FRIDA_MAP_SIZE, sha1_seeds)){
        new_seeds++;
        printf("NEW nr seeds: %ld\n", new_seeds);
        tx.dump_new_cov(iteration, seed_dir, backup_rng);
    }
    iteration += 1;
    FUZZER_LOGI(
        "-------------------------------------------------------------------");
  }
}

void do_replay(char* seed_path){
    Executor executor;
    Transaction tx = deserialize_tx(seed_path, rng);

    ParcelReaderWriter parcelReaderWriter(tx.info["data"], tx.variable, tx.loop,
                                        tx.constraint);
    parcelReaderWriter.initTxWrite(&tx);
    parcelReaderWriter.start();
    tx.dumpsha1(-1);
    executor.run_cov(tx, frida_shared_mem, FRIDA_MAP_SIZE);

    FILE* done_file = fopen(replay_done_path, "w+");
    if (done_file == NULL) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    fprintf(done_file, "%d", 42);
    fclose(done_file); 
}

int main(int argc, char *argv[]) {

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  const char *optstring = "";
  static struct option long_options[] = {
      {"log_level", required_argument, NULL, 'l'},
      {"interface", required_argument, NULL, 'i'},
      {"transaction", required_argument, NULL, 't'},
      {"replay_seed", required_argument, NULL, 's'},
      {"timeout", required_argument, NULL, 'e'},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0}};
  int opt;
  int option_index = 0;
  while ((opt = getopt_long(argc, argv, optstring, long_options,
                            &option_index)) != -1) {
    switch (opt) {
    case 'l': {
      printf("Set log level : %s.\n", optarg);
      if (!strncmp(optarg, "info", 4)) {
        logLevel = INFO_LEVEL;
      } else if (!strncmp(optarg, "debug", 5)) {
        logLevel = DEBUG_LEVEL;
      } else if (!strncmp(optarg, "error", 5)) {
        logLevel = ERROR_LEVEL;
      } else {
        FUZZER_LOGI("Unknown log option %s.", optarg);
        exit(0);
      }
      break;
    }
    case 's': {
        printf("replaying seed: %s.\n", optarg);
        replay_seed = 1;
        seedPath = optarg;
        break;
    }
    case 'i': {
      printf("Set target interface : %s.\n", optarg);
      targetInterface = optarg;
      break;
    }
    case 't': {
      printf("Set target transaction: %s.\n", optarg);
      targetTransaction = optarg;
      break;
    }
    case 'e': {
        timeout = (size_t)(std::stoul(optarg));
        printf("setting timeout : %zu\n", timeout);
        break;
    }
    case '?':
    case 'h': {
      char *help =
          (char *)"Usage: ./native_service_fuzzer [OPTION]\n"
                  "\n"
                  "  --log_level       specify the log level of fuzzer\n"
                  "  --interface       specify the target interface to "
                  "fuzz\n"
                  "  --transaction     specify the target transaction to "
                  "fuzz\n"
                  "  --timeout         specify a timeout for a transaction execution\n"
                  "  --help            help manual\n";
      printf("%s", help);
      exit(0);
    }
    default:
      abort();
    }
  }
  if (targetInterface && targetTransaction) {
    FUZZER_LOGE(
        "Can not specify interface and transaction options at the same time.");
    exit(0);
  }
  init((char *)FUZZER_PATH "model/service/",
       (char *)FUZZER_PATH "model/structure/");

    FILE* pid_file = fopen(pid_path, "w+");
    if (pid_file == NULL) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    fprintf(pid_file, "%d", getpid());
    fclose(pid_file);

  if(replay_seed){
    //TODO
    frida_shared_mem = (unsigned char*)mmap(NULL, FRIDA_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE |MAP_ANONYMOUS, -1, 0);
    do_replay(seedPath);
    exit(0);
  }
   
    int wait_for_pid = 0;
    if(getenv("WAIT_PID")){
        printf("WAIT_PID enabled\n");
        wait_for_pid = 1;
    }

    // wait for pid ack
    if(wait_for_pid){
        printf("[..] waiting for pid_read");
        while(1){
        if(access(pid_ack_path, F_OK) == 0){
            break;
        }
        usleep(500000);
        }
    }
    if(getenv("NOSHM")){
        printf("NOSHM specified, using fake frida shared memory region\n");
        frida_shared_mem = (unsigned char*)mmap(NULL, FRIDA_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE |MAP_ANONYMOUS, -1, 0);
    } else {
        // open the shared memory to the frida instrumentation
        int fd = open(shared_mem_path, O_RDWR);
        if (fd == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        // Map the file into memory
        frida_shared_mem = (unsigned char*)mmap(NULL, FRIDA_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    if (frida_shared_mem == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    printf("__frida_area_ptr: %p\n", frida_shared_mem);

    if(getenv("RELOAD")){
        // reload the coverage mapping file
        reload_cov_map(sha1_seeds);
    }

  startFuzzing();
  return 0;
}

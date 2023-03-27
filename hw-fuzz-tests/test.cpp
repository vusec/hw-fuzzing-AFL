#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <sanitizer/dfsan_interface.h>

dfsan_label label = 1;

const size_t size = 20;

struct Step {
  char storage[size];
  Step(char x) {
    memset(storage, x, size);
  }

  char getCharOrNull(size_t index) {
    index -= '0';
    if (index < size)
      return storage[index];
    return '0';
  }

  void set(size_t i, char x) {
    if (i < size)
      storage[i] = x;
  }
};

__attribute__((noinline))
void target_function(char *buf, size_t len) {
  if (len < 6)
    return;

  Step step1('1');

  dfsan_set_label(label, (void*)(step1.storage + 4), 1);

  Step step2('2');
  step2.set(5, step1.getCharOrNull(*(++buf)));

  Step step3('3');
  step3.set(7, step2.getCharOrNull(*(++buf)));

  Step step4('4');
  step4.set(11, step3.getCharOrNull(*(++buf)));

  Step step5('5');
  step5.set(3, step4.getCharOrNull(*(++buf)));

  if (dfsan_get_label(step5.storage[3]) == label) {
    fprintf(stderr, "Got magic input\n");
    abort();
  }

  step4.storage[size - 1] = 0;
  printf("%s\n", step4.storage);
}


#ifndef persistent
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;

    if (len < 2) continue;

    target_function((char *)(buf), len);

  }

  return 0;

}
#else

int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *string = (char *)malloc(fsize + 1);
  fread(string, fsize, 1, f);
  fclose(f);

  string[fsize] = 0;
  target_function((char *)(string), fsize);
}

#endif

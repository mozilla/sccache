
#include <stdio.h>
#include <hip/hip_runtime.h>

__global__ void cuda_entry_point(int*, int*) {}
__device__ void cuda_device_func(int*, int*) {}

int main() {
  printf("%s says hello world\n", __FILE__);
}

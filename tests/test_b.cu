#include <stdio.h>
#include "cuda_runtime.h"

__device__ void cuda_device_func(int* a) {
  a[0] = 1;
  a[1] = 2;
}

__global__ void cuda_entry_point(int* a) {
  cuda_device_func(a);
}

int main() {
  int* a;
  cudaMalloc(&a, sizeof(int) * 2);
  cuda_entry_point<<<1,1>>>(a);
  int b;
  cudaMemcpy(&b, a, sizeof(int), cudaMemcpyDeviceToHost);
  printf("%s says hello world, result=%d\n", __FILE__, b);
}

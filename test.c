#include <stdio.h>

int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n-1) + fibonacci(n-2);
}

int sum_array(int arr[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}

int main() {
    // フィボナッチ数列の計算
    int fib_result = fibonacci(5);
    printf("Fibonacci(5) = %d\n", fib_result);

    // 配列の合計計算
    int arr[] = {1, 2, 3, 4, 5};
    int arr_sum = sum_array(arr, 5);
    printf("Sum of array = %d\n", arr_sum);

    return 0;
} 
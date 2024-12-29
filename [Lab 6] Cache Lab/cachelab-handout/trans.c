/*
 * trans.c - Matrix transpose B = A^T
 *
 * Each transpose function must have a prototype of the form:
 * void trans(int M, int N, int A[N][M], int B[M][N]);
 *
 * A transpose function is evaluated by counting the number of misses
 * on a 1KB direct mapped cache with a block size of 32 bytes.
 */
#include <stdio.h>
#include "cachelab.h"

int is_transpose(int M, int N, int A[N][M], int B[M][N]);

/*
 * transpose_submit - This is the solution transpose function that you
 *     will be graded on for Part B of the assignment. Do not change
 *     the description string "Transpose submission", as the driver
 *     searches for that string to identify the transpose function to
 *     be graded.
 */
char transpose_submit_desc[] = "Transpose submission";
void transpose_submit(int M, int N, int A[N][M], int B[M][N])
{
    switch (N)
    {
    case 32:
    {
        for (int i = 0; i < 32; i += 8)
        {
            for (int j = 0; j < 32; j += 8)
            {
                if (i != j)
                {
                    for (int ii = 0; ii < 8; ii++)
                        for (int jj = 0; jj < 8; jj++)
                        {
                            B[j + jj][i + ii] = A[i + ii][j + jj];
                        }
                }
                else
                {
                    for (int ii = 0; ii < 8; ii++)
                    {
                        for (int jj = 0; jj < 8; jj++)
                        {
                            if (ii != jj)
                            {
                                B[j + jj][i + ii] = A[i + ii][j + jj];
                            }
                        }
                        B[j + ii][i + ii] = A[i + ii][j + ii];
                    }
                }
            }
        }
        break;
    }
    case 64:
    {
        int a0, a1, a2, a3, a4, a5, a6, a7, temp;

        // without diagonal
        for (int i = 0; i < 64; i += 8)
        {
            for (int j = 0; j < 64; j += 8)
            {
                temp = 56;
                if (i == 56 || j == 56)
                {
                    temp = 0;
                }
                if (j == 0)
                {
                    temp = 8;
                }
                if (i != j)
                {
                    for (int jj = 0; jj < 8; jj++)
                    {
                        B[temp + 4][temp + jj] = A[i + 4][j + jj];
                        B[temp + 5][temp + jj] = A[i + 5][j + jj];
                        B[temp + 6][temp + jj] = A[i + 6][j + jj];
                        B[temp + 7][temp + jj] = A[i + 7][j + jj];
                    }
                    for (int jj = 0; jj < 8; jj++)
                    {
                        B[j + jj][i + 0] = A[i + 0][j + jj];
                        B[j + jj][i + 1] = A[i + 1][j + jj];
                        B[j + jj][i + 2] = A[i + 2][j + jj];
                        B[j + jj][i + 3] = A[i + 3][j + jj];
                        B[j + jj][i + 4] = B[temp + 4][temp + jj];
                        B[j + jj][i + 5] = B[temp + 5][temp + jj];
                        B[j + jj][i + 6] = B[temp + 6][temp + jj];
                        B[j + jj][i + 7] = B[temp + 7][temp + jj];
                    }
                }
            }
        }

        // diagonal (slow)
        for (int i = 0; i < 64; i += 8)
        {
            for (int j = 0; j < 64; j += 8)
            {
                if (i == j)
                {
                    for (int ii = 0; ii < 8; ii++)
                    {
                        a0 = A[i + ii][j + 0];
                        a1 = A[i + ii][j + 1];
                        a2 = A[i + ii][j + 2];
                        a3 = A[i + ii][j + 3];
                        a4 = A[i + ii][j + 4];
                        a5 = A[i + ii][j + 5];
                        a6 = A[i + ii][j + 6];
                        a7 = A[i + ii][j + 7];
                        B[j + 0][i + ii] = a0;
                        B[j + 1][i + ii] = a1;
                        B[j + 2][i + ii] = a2;
                        B[j + 3][i + ii] = a3;
                        B[j + 4][i + ii] = a4;
                        B[j + 5][i + ii] = a5;
                        B[j + 6][i + ii] = a6;
                        B[j + 7][i + ii] = a7;
                    }
                }
            }
        }

        // A -> B (with T, shifted)
        // for (int i = 0; i < 56; i += 8)
        // {
        //     for (int j = 0; j < 8; j++)
        //     {
        //         B[i + 0 + 8][i + j + 8] = A[i + j][i + 0];
        //         B[i + 1 + 8][i + j + 8] = A[i + j][i + 1];
        //         B[i + 2 + 8][i + j + 8] = A[i + j][i + 2];
        //         B[i + 3 + 8][i + j + 8] = A[i + j][i + 3];
        //         B[i + 4 + 8][i + j + 8] = A[i + j][i + 4];
        //         B[i + 5 + 8][i + j + 8] = A[i + j][i + 5];
        //         B[i + 6 + 8][i + j + 8] = A[i + j][i + 6];
        //         B[i + 7 + 8][i + j + 8] = A[i + j][i + 7];
        //     }
        // }
        // for (int i = 0; i < 8; i++)
        // {
        //     B[0][i] = A[56 + i][56 + 0];
        //     B[1][i] = A[56 + i][56 + 1];
        //     B[2][i] = A[56 + i][56 + 2];
        //     B[3][i] = A[56 + i][56 + 3];
        //     B[4][i] = A[56 + i][56 + 4];
        //     B[5][i] = A[56 + i][56 + 5];
        //     B[6][i] = A[56 + i][56 + 6];
        //     B[7][i] = A[56 + i][56 + 7];
        // }

        // B -> B (rev. shift)
        // for (int i = 56; i >= 0; i -= 8)
        // {
        //     a0 = B[i / 8][0];
        //     a1 = B[i / 8][1];
        //     a2 = B[i / 8][2];
        //     a3 = B[i / 8][3];
        //     a4 = B[i / 8][4];
        //     a5 = B[i / 8][5];
        //     a6 = B[i / 8][6];
        //     a7 = B[i / 8][7];
        //     for (int j = 1; j < 8; j++)
        //     {
        //         B[j * 8 + i / 8 - 8][j * 8 + 0 - 8] = B[j * 8 + i / 8][j * 8 + 0];
        //         B[j * 8 + i / 8 - 8][j * 8 + 1 - 8] = B[j * 8 + i / 8][j * 8 + 1];
        //         B[j * 8 + i / 8 - 8][j * 8 + 2 - 8] = B[j * 8 + i / 8][j * 8 + 2];
        //         B[j * 8 + i / 8 - 8][j * 8 + 3 - 8] = B[j * 8 + i / 8][j * 8 + 3];
        //         B[j * 8 + i / 8 - 8][j * 8 + 4 - 8] = B[j * 8 + i / 8][j * 8 + 4];
        //         B[j * 8 + i / 8 - 8][j * 8 + 5 - 8] = B[j * 8 + i / 8][j * 8 + 5];
        //         B[j * 8 + i / 8 - 8][j * 8 + 6 - 8] = B[j * 8 + i / 8][j * 8 + 6];
        //         B[j * 8 + i / 8 - 8][j * 8 + 7 - 8] = B[j * 8 + i / 8][j * 8 + 7];
        //     }
        //     B[56 + i / 8][56] = a0;
        //     B[56 + i / 8][57] = a1;
        //     B[56 + i / 8][58] = a2;
        //     B[56 + i / 8][59] = a3;
        //     B[56 + i / 8][60] = a4;
        //     B[56 + i / 8][61] = a5;
        //     B[56 + i / 8][62] = a6;
        //     B[56 + i / 8][63] = a7;
        // }
        break;
    }
    case 67:
    {
        for (int i = 0; i < 67; i += 16)
        {
            for (int j = 0; j < 61; j += 16)
            {
                for (int ii = 0; ii < 16 && i + ii < 67; ii++)
                {
                    for (int jj = 0; jj < 16 && j + jj < 61; jj++)
                    {
                        B[j + jj][i + ii] = A[i + ii][j + jj];
                    }
                }
            }
        }
        break;
    }
    default:
        break;
    }
}
/*
 * You can define additional transpose functions below. We've defined
 * a simple one below to help you get started.
 */

/*
 * trans - A simple baseline transpose function, not optimized for the cache.
 */
char trans_desc[] = "Simple row-wise scan transpose";
void trans(int M, int N, int A[N][M], int B[M][N])
{
    int i, j, tmp;

    for (i = 0; i < N; i++)
    {
        for (j = 0; j < M; j++)
        {
            tmp = A[i][j];
            B[j][i] = tmp;
        }
    }
}

/*
 * registerFunctions - This function registers your transpose
 *     functions with the driver.  At runtime, the driver will
 *     evaluate each of the registered functions and summarize their
 *     performance. This is a handy way to experiment with different
 *     transpose strategies.
 */
void registerFunctions()
{
    /* Register your solution function */
    registerTransFunction(transpose_submit, transpose_submit_desc);

    /* Register any additional transpose functions */
    // registerTransFunction(trans, trans_desc);
}

/*
 * is_transpose - This helper function checks if B is the transpose of
 *     A. You can check the correctness of your transpose by calling
 *     it before returning from the transpose function.
 */
int is_transpose(int M, int N, int A[N][M], int B[M][N])
{
    int i, j;

    for (i = 0; i < N; i++)
    {
        for (j = 0; j < M; ++j)
        {
            if (A[i][j] != B[j][i])
            {
                return 0;
            }
        }
    }
    return 1;
}

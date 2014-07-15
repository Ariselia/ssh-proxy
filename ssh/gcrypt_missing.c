#include <stdlib.h>

#include "ssh/priv.h"
#include "ssh/ssh-gcrypt.h"

#ifdef HAVE_LIBGCRYPT
int my_gcry_dec2bn(bignum *bn, const char *data) {
  int count;

  *bn = bignum_new();
  if (*bn == NULL) {
    return 0;
  }
  gcry_mpi_set_ui(*bn, 0);
  for (count = 0; data[count]; count++) {
    gcry_mpi_mul_ui(*bn, *bn, 10);
    gcry_mpi_add_ui(*bn, *bn, data[count] - '0');
  }

  return count;
}

char *my_gcry_bn2dec(bignum bn) {
  bignum bndup, num, ten;
  char *ret;
  int count, count2;
  int size, rsize;
  char decnum;

  size = gcry_mpi_get_nbits(bn) * 3;
  rsize = size / 10 + size / 1000 + 2;

  ret = malloc(rsize + 1);
  if (ret == NULL) {
    return NULL;
  }

  if (!gcry_mpi_cmp_ui(bn, 0)) {
    strcpy(ret, "0");
  } else {
    ten = bignum_new();
    if (ten == NULL) {
      SAFE_FREE(ret);
      return NULL;
    }

    num = bignum_new();
    if (num == NULL) {
      SAFE_FREE(ret);
      bignum_free(ten);
      return NULL;
    }

    for (bndup = gcry_mpi_copy(bn), bignum_set_word(ten, 10), count = rsize;
        count; count--) {
      gcry_mpi_div(bndup, num, bndup, ten, 0);
      for (decnum = 0, count2 = gcry_mpi_get_nbits(num); count2;
          decnum *= 2, decnum += (gcry_mpi_test_bit(num, count2 - 1) ? 1 : 0),
          count2--)
        ;
      ret[count - 1] = decnum + '0';
    }
    for (count = 0; count < rsize && ret[count] == '0'; count++)
      ;
    for (count2 = 0; count2 < rsize - count; ++count2) {
      ret[count2] = ret[count2 + count];
    }
    ret[count2] = 0;
    bignum_free(num);
    bignum_free(bndup);
    bignum_free(ten);
  }

  return ret;
}

#endif
/* vim: set ts=2 sw=2 et cindent: */

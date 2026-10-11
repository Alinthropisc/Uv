#include <stddef.h>
#undef NDEBUG
#include <assert.h>
#include <climits>

#include "nbase.h"

// Character pool memory allocation
#include "azula_charpool.hh"
#include "azula_errors.hh"

static azula::AzulaCharPool g_charpool (16384);


class AzulaStrTable
{
    public:
        AzulaStrTable()
        {
            memset(table, 0, sizeof(table));

            for (int i = 0; i <= CHAR_MAX; i++)
            {
                table[i*2] = static_cast<char>(i);
            }
        }

        const char *azula_get(char c)
        {
            assert(c >= 0);
            return &table[c*2];
        } 

    private:
        char table[2*(CHAR_MAX + 1)];
}

const char *azula::azula_cp_strndup(const char *src, int len)
{
  return g_charpool.azula_dup(src, len);
}

const char *azula::azula_cp_strdup(const char *src)
{
  return g_charpool.azula_dup(src);
}

void azula::azula_cp_free(void)
{
  return g_charpool.azula_clear();
}



azula::AzulaCharPool::AzulaCharPool(size_t init_sz)
{

}


void azula::AzulaCharPool::azula_clear(void)
{

}



const char *azula::AzulaCharPool::azula_dup(const char *src, int len)
{

}













































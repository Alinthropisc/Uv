#pragma once

#include <cstddef>
#include <vector>



namespace azula
{
    typedef std::vector<char *> AzulaBucketList;

    const char *azula_cp_strndup(const char *src, int len);
    const char *azula_cp_strdup(const char *src);
    const char *azula_cp_char2str(char *c);

    void azula_cp_free(void);

    class AzulaCharPool
    {
        private:
            AzulaBucketList bucket_lists;
            size_t currentbucketsz;
            size_t nexti;

        public:
            AzulaCharPool();
            ~AzulaCharPool();
            
            void azula_clear();
            
            const char *azula_dup(const char *src, int len = 1);
    };
}






























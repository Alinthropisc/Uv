#pragma once


#include <queue>
#include <set>
#include <string>





namespace azula
{
    // Adding new targets is for NSE scripts 
    class AzulaNewTargets
    {
        public:
            // return a previous inserted target
            static std::string azula_read(void);
            // get the number of all new added targets
            static unsigned long azula_get_number(void);
            // get the number of queued targets left to scan
            static unsigned long azula_get_queued(void);
            // Free the new_targets object
            static void azula_free_new_targets(void);
            // insert targets to the new_targets_queue
            static unsigned long azula_insert(const char *target);

        private:
            AzulaNewTargets();
            // A queue to push new targets that were discovered by NSE scripts.
            // Azula will pop future targets from this queue. 
            std::queue<std::string> queue;

            // A cache to save scanned targets specifications.
            // (These are targets that were pushed to Nmap scan queue)
            std::set<std::string> history;

            // Save new targets onto the queue
            unsigned long push (const char *target);

            static AzulaNewTargets *new_targets;
    };
}












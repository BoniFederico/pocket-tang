#include "pt/pt_version.h"
#include "unity.h"
#include <string.h>

void setUp(void)
{
}
void tearDown(void)
{
}

static void test_version_is_nonempty(void)
{
    TEST_ASSERT_NOT_NULL(pt_version());
    TEST_ASSERT_GREATER_THAN(0, strlen(pt_version()));
    TEST_ASSERT_EQUAL_STRING(PT_VERSION, pt_version());
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_version_is_nonempty);
    return UNITY_END();
}

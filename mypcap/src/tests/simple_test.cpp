#include <gtest/gtest.h>

int sum(const int a, const int b)
{
	return a + b;
}


TEST(ADDTEST, TC1)
{
	EXPECT_EQ(2, sum(1, 1));
}


TEST(ADDTEST, TC2)
{
	EXPECT_EQ(3, sum(1, 2));
}

TEST(ADDTEST, TC3)
{
	EXPECT_EQ(0, sum(-2, 1));
}

int main(int argc, char** argv) 
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

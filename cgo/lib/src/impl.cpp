#include "myheader.hpp"

#include <iostream>

template <typename func>
void inner(func f) {
	f();
}


int myadd(int a, int b)
{
	auto A = a;
	auto B = b;
	
	const auto func = [&A, &B]() {
		std::cout << "lambda" << std::endl;
		std::cout << A << " " << B << '\n';
		A *= A;
		B *= B;
	};

	inner(func);

	return A + B;
	
}

#pragma once

#include "stdafx.h"

namespace grr
{
	class pe_loader_exception : public std::exception
	{
	public:
		explicit pe_loader_exception(const char* message) :
			message_(message)
		{}

		explicit pe_loader_exception(const std::string& message) :
			message_(message)
		{}

		virtual ~pe_loader_exception() throw () {}

		virtual const char* what() const throw ()
		{
			return message_.c_str();
		}

	protected:
		std::string message_;
	};
}
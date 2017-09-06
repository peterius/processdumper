#include "justforvs.h"
#include "functionprototypes.h"

/* From the internet : 'brofield' on stackoverflow.com regarding VS and string literals: */
const char * ConvertToUTF8(const wchar_t * pStr) {
	static char szBuf[1024];
	WideCharToMultiByte_0(CP_UTF8, 0, pStr, -1, szBuf, sizeof(szBuf), NULL, NULL);
	return szBuf;
}
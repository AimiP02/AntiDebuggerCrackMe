#include "pch.h"

#include "Utils.h"

PPEB GetPEB() {
#if defined (ENV64BIT)
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#elif defined (ENV32BIT)
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	return pPEB;
}

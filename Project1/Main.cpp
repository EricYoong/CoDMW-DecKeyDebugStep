#include <Windows.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <DbgHelp.h>
#include <iomanip>
#pragma comment(lib,"DbgHelp.lib")

// debugger status
enum class DebuggeeStatus
{
	NONE,
	SUSPENDED,
	INTERRUPTED
};
bool bExcept = false;
class CDebugger {
public:
	bool DEBUG = !true;//dbg mode
	struct LineInfo {
		std::string filePath;
		DWORD lineNumber;
	};
	// flag
	struct Flag
	{
		DWORD continueStatus;
		DWORD resetUserBreakPointAddress;
		bool isBeingStepOver;
		bool isBeingStepOut;
		bool isBeingSingleInstruction;
		LineInfo glf;
	} FLAG;
	// breakpoint
	struct BreakPoint
	{
		DWORD64 address;
		BYTE content;
	};
	BreakPoint bpStepOver;
	DebuggeeStatus debuggeeStatus;
	DWORD continueStatus;
	HANDLE debuggeehProcess;
	HANDLE debuggeehThread;
	DWORD debuggeeprocessID;
	DWORD debuggeethreadID;

	DWORD64 procBase;
	void InitProcess() {
		static int iInit = 0;
		STARTUPINFOA startupinfo = { 0 };
		startupinfo.cb = sizeof(startupinfo);
		PROCESS_INFORMATION processinfo = { 0 };
		unsigned int creationflags = DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NEW_CONSOLE;

		if (CreateProcessA(
			//"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 08-04.exe",
			//"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 15-04.exe",
			//iInit++ == 0 ? "C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 21-04.exe" : "C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 23-04.exe"
			//iInit++ == 0 ? "C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 23-04.exe" : "C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 25-04.exe"
			//iInit++ == 0 ? "C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 25-04.exe" : "C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 27-04.exe"
			//iInit++ == 0 ? "C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 27-04.exe" : 
			//"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 29-04.exe"
			//"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 03-05.exe"
			//"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 05-05.exe"
			"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 07-05.exe"
			//"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 23-04.exe"
			,NULL,
			NULL,
			NULL,
			FALSE,
			creationflags,
			NULL,
			NULL,
			&startupinfo,
			&processinfo) == FALSE)
		{
			std::cout << "CreateProcess failed: " << GetLastError() << std::endl;
			return;
		}

		debuggeehProcess = processinfo.hProcess;
		debuggeehThread = processinfo.hThread;
		debuggeeprocessID = processinfo.dwProcessId;
		debuggeethreadID = processinfo.dwThreadId;

		auto c = dbg.GetContext();
		procBase = dbg.Read <DWORD64>(c.Rdx + 0x10);

		debuggeeStatus = DebuggeeStatus::SUSPENDED;
		printf("T[%i] P[%04X] Process launched and suspended. [%p]\n", debuggeethreadID,debuggeeprocessID, procBase);
	}
	CONTEXT GetContext()
	{
		CONTEXT c;
		c.ContextFlags = CONTEXT_ALL;

		if (GetThreadContext(this->debuggeehThread, &c))
		{
			//return false;
		}
		return c;
	}
	void SetContext(CONTEXT* c) {
		SetThreadContext(debuggeehThread, c);
	}
	void setCPUTrapFlag()
	{
		CONTEXT c = GetContext();
		c.EFlags |= 0x100;
		SetContext(&c);
	}
	void Run() {
		if (debuggeeStatus == DebuggeeStatus::NONE)
		{
			//std::cout << "Debuggee is not started yet." << std::endl;
			return;
		}
		if (debuggeeStatus == DebuggeeStatus::SUSPENDED)
		{
			//std::cout << "Continue to run." << std::endl;
			ResumeThread(debuggeehThread);
		}
		else
		{
			ContinueDebugEvent(debuggeeprocessID, debuggeethreadID, FLAG.continueStatus);
			//printf("goocci\n");
		}

		DEBUG_EVENT debugEvent;
		while (WaitForDebugEvent(&debugEvent, INFINITE) == TRUE)
		{
			debuggeeprocessID = debugEvent.dwProcessId;
			debuggeethreadID = debugEvent.dwThreadId;
			if (DispatchDebugEvent(debugEvent) == TRUE)
			{
				ContinueDebugEvent(debuggeeprocessID, debuggeethreadID, FLAG.continueStatus);
			}
			else {
				break;
			}
		}
	}
	void StepIn() {
		setCPUTrapFlag();
		FLAG.isBeingSingleInstruction = true;
		Run();
	}
	void resetBreakPointHandler()
	{
		/*bpUserList.clear();
		isInitBpSet = false;

		bpStepOut.address = 0;
		bpStepOver.content = 0;*/

		//bpStepOver.address = 0;
		//bpStepOut.content = 0;

		FLAG.continueStatus = DBG_CONTINUE;
		FLAG.isBeingSingleInstruction = false;
		FLAG.isBeingStepOut = false;
		FLAG.isBeingStepOver = false;
		FLAG.resetUserBreakPointAddress = 0;
		FLAG.glf.lineNumber = 0;
		FLAG.glf.filePath = std::string();

		//moduleMap.clear();
	}
	bool OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* pInfo)
	{
		std::cout << "Debuggee created." << std::endl;

		this->resetBreakPointHandler();

		if (SymInitialize(debuggeehProcess, NULL, FALSE) == TRUE)
		{
			DWORD64 moduleAddress = SymLoadModule64(
				debuggeehProcess,
				pInfo->hFile,
				NULL,
				NULL,
				(DWORD64)pInfo->lpBaseOfImage,
				0
			);
			if (moduleAddress == 0)
			{
				std::cout << "SymLoadModule64 failed: " << GetLastError() << std::endl;
			}
			else {
				// set entry stop 
				//setDebuggeeEntryPoint();
			}
		}
		else
		{
			std::cout << "SymInitialize failed: " << GetLastError() << std::endl;
		}
		return true;
	}
	enum class BpType
	{
		INIT,
		STEP_OVER,
		STEP_OUT,
		USER,
		CODE
	};
	BpType getBreakPointType(DWORD addr) {
		static bool isInitBpSet = false;
		if (isInitBpSet == false)
		{
			isInitBpSet = true;
			return BpType::INIT;
		}
		return BpType::CODE;
	}
	bool OnBreakPoint(const EXCEPTION_DEBUG_INFO* pInfo)
	{
		auto bpType = getBreakPointType((DWORD)(pInfo->ExceptionRecord.ExceptionAddress));
		printf("bp type: %i\n", bpType);
		switch (bpType)
		{
		case BpType::INIT:
			FLAG.continueStatus = DBG_CONTINUE;
			//auto c = GetContext();
			//c.Rip = procBase + 0xE74D84;
			//dbg.SetContext(&c);
			return true;

		/*case BpType::CODE:
			return onNormalBreakPoint(pInfo);

		case BpType::STEP_OVER:
			deleteStepOverBreakPoint();
			backwardDebuggeeEIP();
			return onSingleStepCommonProcedures();

		case BpType::USER:
			return onUserBreakPoint(pInfo);

		case BpType::STEP_OUT:
			return onStepOutBreakPoint(pInfo);*/
		}

		return true;
	}
	bool getCurrentLineInfo(LineInfo& lf)
	{
		CONTEXT context = GetContext();

		DWORD displacement;
		IMAGEHLP_LINE64 lineInfo = { 0 };
		lineInfo.SizeOfStruct = sizeof(lineInfo);

		if (SymGetLineFromAddr64(
			debuggeehProcess,
			context.Rip,
			&displacement,
			&lineInfo) == TRUE) {

			lf.filePath = std::string(lineInfo.FileName);
			lf.lineNumber = lineInfo.LineNumber;

			return true;
		}
		else {
			lf.filePath = std::string();
			lf.lineNumber = 0;

			return false;
		}
	}
	bool isLineChanged()
	{
		LineInfo lf;
		if (false == getCurrentLineInfo(lf))
		{
			return false;
		}

		if (lf.lineNumber == FLAG.glf.lineNumber &&
			lf.filePath == FLAG.glf.filePath)
		{
			return false;
		}

		return true;
	}
	int isCallInstruction(DWORD64 addr)
	{
		BYTE instruction[10];

		size_t nRead;
		ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, instruction, 10, &nRead);

		switch (instruction[0]) {

		case 0xE8:
			return 5;

		case 0x9A:
			return 7;

		case 0xFF:
			switch (instruction[1]) {

			case 0x10:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x16:
			case 0x17:
			case 0xD0:
			case 0xD1:
			case 0xD2:
			case 0xD3:
			case 0xD4:
			case 0xD5:
			case 0xD6:
			case 0xD7:
				return 2;

			case 0x14:
			case 0x50:
			case 0x51:
			case 0x52:
			case 0x53:
			case 0x54:
			case 0x55:
			case 0x56:
			case 0x57:
				return 3;

			case 0x15:
			case 0x90:
			case 0x91:
			case 0x92:
			case 0x93:
			case 0x95:
			case 0x96:
			case 0x97:
				return 6;

			case 0x94:
				return 7;
			}

		default:
			return 0;
		}
	}
	void ReadTo(DWORD64 addr, LPBYTE dest, DWORD nSize) {
		size_t nRead;
		ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, dest, nSize, &nRead);
	}
	template <class T>
	T Read(DWORD64 addr) {
		T out;
		size_t nRead;
		ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, &out, sizeof(T), &nRead);
		return out;
	}
	template <class T>
	void Write(DWORD64 addr,T t) {
		size_t nRead;
		WriteProcessMemory(debuggeehProcess, (LPVOID)addr, &t, sizeof(T), &nRead);
	}
	BYTE setBreakPointAt(DWORD64 addr)
	{
		BYTE byte = Read<BYTE>(addr);
		//readDebuggeeMemory(addr, 1, &byte);

		Write<BYTE>(addr,0xCC);//BYTE intInst = 0xCC;
		//writeDebuggeeMemory(addr, 1, &intInst);
		return byte;
	}
	void setStepOverBreakPointAt(DWORD64 addr)
	{
		bpStepOver.address = addr;
		bpStepOver.content = setBreakPointAt(addr);
	}
	bool OnSingleStepCommonProcedures()
	{
		if (isLineChanged() == false)
		{
			if (true == FLAG.isBeingStepOver)
			{
				CONTEXT c = GetContext();
				int pass = isCallInstruction(c.Rip);

				if (pass != 0)
				{
					setStepOverBreakPointAt(c.Rip + pass);
					FLAG.isBeingSingleInstruction = false;
				}
				else {
					setCPUTrapFlag();
					FLAG.isBeingSingleInstruction = true;
				}
			}
			else {
				setCPUTrapFlag();
				FLAG.isBeingSingleInstruction = true;
			}

			FLAG.continueStatus = DBG_CONTINUE;
			return true;
		}

		if (FLAG.isBeingStepOver == true)
		{
			FLAG.isBeingStepOver = false;
		}

		debuggeeStatus = DebuggeeStatus::INTERRUPTED;

		return false;
	}
	bool OnSingleStepTrap(const EXCEPTION_DEBUG_INFO* pInfo)
	{
		/*auto resetUserBreakPoint = [this]() -> void
		{
			for (auto it = this->bpUserList.begin();
				it != this->bpUserList.end();
				++it)
			{
				if (it->address == this->FLAG.resetUserBreakPointAddress)
				{
					setBreakPointAt(it->address);
					this->FLAG.resetUserBreakPointAddress = 0;
				}
			}
		};

		if (FLAG.resetUserBreakPointAddress)
		{
			ResetUserBreakPoint();
		}*/

		if (true == FLAG.isBeingSingleInstruction)
		{
			return  OnSingleStepCommonProcedures();
		}

		FLAG.continueStatus = DBG_CONTINUE;
		return true;
	}
	bool bGotSingleStep = false;
	bool OnException(const EXCEPTION_DEBUG_INFO* pInfo)
	{
		if (DEBUG == true)
		{
			std::cout << "An exception has occured " << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
				<< pInfo->ExceptionRecord.ExceptionAddress << " - Exception code: " << pInfo->ExceptionRecord.ExceptionCode << std::dec << std::endl;
		}

		switch (pInfo->ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_BREAKPOINT:
			return OnBreakPoint(pInfo);
		case EXCEPTION_SINGLE_STEP:
			bGotSingleStep = true;
			debuggeeStatus = DebuggeeStatus::INTERRUPTED;
			return false;// OnSingleStepTrap(pInfo);
			break;
		case 0xC0000005:
			debuggeeStatus = DebuggeeStatus::INTERRUPTED;
			bExcept = true;
			printf("%p - access violation!!!\n", pInfo->ExceptionRecord.ExceptionAddress);
			return false;//
			break;
		}

		if (pInfo->dwFirstChance == TRUE)
		{
			if (DEBUG == true)
			{
				std::cout << "First chance." << std::endl;
			}
		}
		else
		{
			if (DEBUG == true)
			{
				std::cout << "Second chance." << std::endl;
			}
		}

		debuggeeStatus = DebuggeeStatus::INTERRUPTED;
		return false;
	}
	bool DispatchDebugEvent(const DEBUG_EVENT& debugEvent) {

		switch (debugEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			 OnProcessCreated(&debugEvent.u.CreateProcessInfo);
			 return true;
		case CREATE_THREAD_DEBUG_EVENT:
			//printf("Thread created!\n");
			return true;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			//wprintf(L"dll loaded.. %p\n", debugEvent.u.LoadDll.lpBaseOfDll);
			return true;// onDllLoaded(&debugEvent.u.LoadDll);
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			//wprintf(L"dll unloaded.. %p\n", debugEvent.u.LoadDll.lpBaseOfDll);
			return true;// onDllLoaded(&debugEvent.u.LoadDll);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//printf("Thread Exit!\n");
			return true;// onThreadExited(&debugEvent.u.ExitThread);
			break;
		case EXCEPTION_DEBUG_EVENT:
			//printf("[%i] debug event\n", debugEvent.dwThreadId);
			return OnException(&debugEvent.u.Exception);
			break;
		default:

			printf("UNK event: %i\n", debugEvent.dwDebugEventCode);
			break;
		}
		return false;
	}
	void SingleStep() {

		setCPUTrapFlag();
		FLAG.isBeingSingleInstruction = true;
		Run();
	}
} dbg;
void ShowCtx(CONTEXT c) {
	printf("RAX: %p\n", c.Rax);
	printf("RBX: %p\n", c.Rbx);
	printf("RCX: %p\n", c.Rcx);
	printf("RDX: %p\n", c.Rdx);
	printf("RBP: %p\n", c.Rbp);
	printf("RSP: %p\n", c.Rsp);
	printf("RSI: %p\n", c.Rsi);
	printf("RDI: %p\n", c.Rdi);
}

template <class T>
T Read(DWORD64 adr) {
	T t = T();
	ReadProcessMemory(dbg.debuggeehProcess, (LPBYTE)adr, &t, sizeof(T), NULL);
	return t;
}
template <class T>
T Read(LPBYTE adr) {
	T t = T();
	ReadProcessMemory(dbg.debuggeehProcess, (LPBYTE)adr, &t, sizeof(T), NULL);
	return t;
}

template <class T>
void Write(DWORD64 adr,T t) {
	WriteProcessMemory(dbg.debuggeehProcess, (LPBYTE)adr, &t, sizeof(T), NULL);
}
#include <inttypes.h>
#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")
ZydisDecoder decoder;

struct FRev {
	DWORD64 pEncrypt;
	DWORD64 pReverse;
	BYTE bXor;
	DWORD64 keys[16][4];
};

DWORD64 GetReg(BYTE bReg, CONTEXT c) {
	DWORD64 pReg = 0;
	switch (bReg) {
	case ZYDIS_REGISTER_RAX:
		pReg = c.Rax;
		break;
	case ZYDIS_REGISTER_RDX:
		pReg = c.Rdx;
		break;
	case ZYDIS_REGISTER_RBX:
		pReg = c.Rbx;
		break;
	case ZYDIS_REGISTER_RCX:
		pReg = c.Rcx;
		break;
	case ZYDIS_REGISTER_RBP:
		pReg = c.Rbp;
		break;
	case ZYDIS_REGISTER_RSI:
		pReg = c.Rsi;
		break;
	case ZYDIS_REGISTER_RDI:
		pReg = c.Rdi;
		break;
	case ZYDIS_REGISTER_R8:
		pReg = c.R8;
		break;
	case ZYDIS_REGISTER_R9:
		pReg = c.R9;
		break;
	case ZYDIS_REGISTER_R10:
		pReg = c.R10;
		break;
	case ZYDIS_REGISTER_R11:
		pReg = c.R11;
		break;
	case ZYDIS_REGISTER_R12:
		pReg = c.R12;
		break;
	case ZYDIS_REGISTER_R13:
		pReg = c.R13;
		break;
	case ZYDIS_REGISTER_R14:
		pReg = c.R14;
		break;
	case ZYDIS_REGISTER_R15:
		pReg = c.R15;
		break;
	default:
		printf("unk good zydis %i / %p\n", pReg, c.Rip);
		break;
	}
	return pReg;
}

DWORD64 DumpFnc(FRev &rev,DWORD idx, DWORD64 pCmpJA, DWORD64 pSetReg = 0, bool bShowDisp = false,bool bRdy = false) {
	DWORD DISP_VALUE = 0;
	DWORD64 dwRet = 0;
	CONTEXT c;
	c = dbg.GetContext();

	DWORD64 imulExpect = Read<DWORD64>(dbg.procBase + rev.pEncrypt);
	//find call [fnc ] above  84 C0 74 04 B0 01 EB 02 32 C0 85 DB 74 4C 3B DE 7D 48
	if (pSetReg) {
		c.Rip = pSetReg;
		c.Rcx = idx; //fnc index
		c.R8 = 0;
		dbg.SetContext(&c);

		dbg.SingleStep();
		c = dbg.GetContext();
	}
	else {
		//not set reg
		c.Rdi = 0;
		c.Rcx = idx;
	}
	c.Rip = pCmpJA;
	dbg.SetContext(&c);
	if (!bRdy) {
		dbg.SingleStep();
		c = dbg.GetContext();

		dbg.SingleStep();
		c = dbg.GetContext();

		dbg.SingleStep();
		c = dbg.GetContext();
		dwRet = c.Rax;
	}


	// Loop over the instructions in our buffer.
	// The IP is chosen arbitrary here in order to better visualize
	// relative addressing.
	uint64_t instructionPointer = 0x007FFFFFFF400000;
	size_t offset = 0;
	ZydisDecodedInstruction instruction;

	DWORD64 oldRip = 0;
	DWORD iImul = 0;
	bool bLastKey = false;
	DWORD64 dwKeys[4] = { 0,0,0,0 };
	DWORD iRev = 0;
	bool bPrint = true;

	
	
	while(iImul<4) {
		BYTE bRead[20];
		dbg.ReadTo(c.Rip, bRead, 20);
		bool goodDec = ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
			&decoder, bRead, 20,
			instructionPointer, &instruction));
		//printf("%i %p / %p X has DIPS %i / %p\n", bRdy, c.Rax, c.Rip, instruction.operands[1].mem.disp.hasDisplacement, instruction.operands[1].mem.disp.value);
		if (!goodDec) break;

		if (!bRdy && instruction.mnemonic == ZYDIS_MNEMONIC_JMP) bRdy = true;
		else if(bRdy){
			if ((instruction.mnemonic == ZYDIS_MNEMONIC_MOV || instruction.mnemonic == ZYDIS_MNEMONIC_IMUL || instruction.mnemonic == ZYDIS_MNEMONIC_XOR) && instruction.operands[1].mem.disp.hasDisplacement) {//&& instruction.operands[1].mem.disp.value == DISP_VALUE) {
				 //printf("%i %p / %p X has DIPS %i / %p\n", bRdy,c.Rax, c.Rip, instruction.operands[1].mem.disp.hasDisplacement, instruction.operands[1].mem.disp.value);
				if (instruction.operands[1].mem.disp.value < 0x50) {
					//printf("has DIPS %p\n", c.Rip);
					if (instruction.operands[1].mem.disp.value < 0x32) {
						if (!DISP_VALUE && bPrint && bShowDisp) {
							bPrint = false;
							DISP_VALUE = instruction.operands[1].mem.disp.value;
							rev.bXor = DISP_VALUE;
							//printf("found DISPLACEMENT! %04X //%p\n", DISP_VALUE,c.Rip);
							if (!iRev && bShowDisp) {
								auto pRead = c.Rip - 10;
								auto rRev = pRead + 7 + Read<DWORD>(pRead + 3) - dbg.procBase;
								if (rRev != rev.pEncrypt) {
									iRev = rRev;
									//printf("DWORD REVERSED_ADDRESS = 0x%08X; //%p\n", iRev,c.Rip);
									rev.pReverse = iRev;
								}
							}
						}
						
						bLastKey = true;
					}
					//skip
					c = dbg.GetContext();
					c.Rip += instruction.length; //fnc index
					if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL) {
						//printf("isImul %i\n", iImul);
						bLastKey = false;
						iImul++;//skip lastKey
					}
					dbg.SetContext(&c);
					continue;
				}
				else if (!iRev && bShowDisp) {
					
					DWORD pPtr = c.Rip + 7 + instruction.operands[1].mem.disp.value - dbg.procBase;
					if (pPtr != rev.pEncrypt) {
						//printf("DWORD REVERSED_ADDRESS = 0x%08X; //%p\n", pPtr,c.Rip);
						iRev = pPtr;
						rev.pReverse = iRev;
					}
				}

			}
		}
		if (bExcept) { //we got an exception? so best to skip for safety
			printf("got except %p\n", c.Rip);
			bExcept = false;
			c = dbg.GetContext();
			c.Rip += instruction.length; //fnc index
			dbg.SetContext(&c);
			continue;
		}
		oldRip = c.Rip;
		dbg.SingleStep();

		c = dbg.GetContext();
		DWORD nInstructSize = c.Rip - oldRip;

		{
			if (goodDec && instruction.mnemonic == ZYDIS_MNEMONIC_IMUL) {
				bool bGoodImul = false;
				DWORD64 pReg = 0;
				//if (!bLastKey) {
					DWORD64 reg1 = GetReg(instruction.operands[1].reg.value,c);
					pReg = reg1;
					DWORD64 reg0 = GetReg(instruction.operands[0].reg.value, c);
					//printf("%p %i-%i imul / { %p / %p } %p\n", imulExpect, idx, iImul, reg0,reg1,oldRip);
					if (reg0 == imulExpect) {
						bGoodImul = true;
					}
				//}
				if (bGoodImul) {
					//printf("GOOD %p %i-%i imul / { %p / %p } %p\n", imulExpect, idx, iImul, pReg, 0, oldRip);
					dwKeys[iImul++] = pReg;
					bLastKey = false;
					if (iImul >= 4)break;
					//calc next
					//no need, xor is always 0
				}
			}
			//check if imul
		}
	}

	bool bGen = false;
	for (DWORD i = 0; i < 4; i++) rev.keys[idx][i] = dwKeys[i];
	if (bGen) {
		if (dwKeys[0] == 0) printf("key[%i][0] = LastKey;\n",idx); else printf("key[%i][0] = 0x%p;\n", idx, dwKeys[0]);
		if (dwKeys[1] == 0) printf("key[%i][1] = LastKey;\n",idx); else 		printf("key[%i][1] = 0x%p;\n", idx, dwKeys[1]);
		if (dwKeys[2] == 0) printf("key[%i][2] = LastKey;\n", idx); else printf("key[%i][2] = 0x%p;\n", idx, dwKeys[2]);
		if (dwKeys[3] == 0) printf("key[%i][3] = LastKey;\n\n", idx); else printf("key[%i][3] = 0x%p;\n\n", idx, dwKeys[3]);
	}
	else {
		//printf("%p - keys[%i] = { %p , %p , %p , %p }\n",dwRet, idx,dwKeys[0], dwKeys[1], dwKeys[2], dwKeys[3]);
		//printf("key[%i] = { 0x%p , 0x%p , 0x%p , 0x%p }\n", idx, dwKeys[0], dwKeys[1], dwKeys[2], dwKeys[3]);
	}

	return dwRet;
}

#include <vector>
#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD))
#define PEFHDROFFSET(a) (PIMAGE_FILE_HEADER)((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
#define SECHDROFFSET(ptr) (PIMAGE_SECTION_HEADER)((LPVOID)((BYTE *)(ptr)+((PIMAGE_DOS_HEADER)(ptr))->e_lfanew+SIZE_OF_NT_SIGNATURE+sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER)))

PIMAGE_SECTION_HEADER getCodeSection(LPVOID lpHeader) {
	PIMAGE_FILE_HEADER pfh = PEFHDROFFSET(lpHeader);
	if (pfh->NumberOfSections < 1)
	{
		return NULL;
	}
	PIMAGE_SECTION_HEADER psh = SECHDROFFSET(lpHeader);
	return psh;
}
size_t replace_all(std::string& str, const std::string& from, const std::string& to) {
	size_t count = 0;

	size_t pos = 0;
	while ((pos = str.find(from, pos)) != std::string::npos) {
		str.replace(pos, from.length(), to);
		pos += to.length();
		++count;
	}

	return count;
}

bool is_hex_char(const char& c) {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
}
std::vector<int> pattern(std::string patternstring) {
	std::vector<int> result;
	const uint8_t hashmap[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
	};
	replace_all(patternstring, "??", " ? ");
	replace_all(patternstring, "?", " ?? ");
	replace_all(patternstring, " ", "");
	//boost::trim(patternstring);
	//assert(patternstring.size() % 2 == 0);
	for (std::size_t i = 0; i < patternstring.size() - 1; i += 2) {
		if (patternstring[i] == '?' && patternstring[i + 1] == '?') {
			result.push_back(0xFFFF);
			continue;
		}
		//assert(is_hex_char(patternstring[i]) && is_hex_char(patternstring[i + 1]));
		result.push_back((uint8_t)(hashmap[patternstring[i]] << 4) | hashmap[patternstring[i + 1]]);
	}
	return result;
}

std::vector<std::size_t> find_pattern(const uint8_t* data, std::size_t data_size, const std::vector<int>& pattern) {
	// simple pattern searching, nothing fancy. boyer moore horsepool or similar can be applied here to improve performance
	std::vector<std::size_t> result;
	for (std::size_t i = 0; i < data_size - pattern.size() + 1; i++) {
		std::size_t j;
		for (j = 0; j < pattern.size(); j++) {
			if (pattern[j] == 0xFFFF) {
				continue;
			}
			if (pattern[j] != data[i + j]) {
				break;
			}
		}
		if (j == pattern.size()) {
			result.push_back(i);
		}
	}
	return result;
}
#include <Psapi.h>
HMODULE GetModuleBaseAddress(HANDLE handle) {
	HMODULE hMods[1024];
	DWORD   cbNeeded;

	if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
		//MessageBoxA(0, "GetBase ErrorY2", "ErrorY2", 0);
		return hMods[0];
	}
	MessageBoxA(0, "GetBase ErrorX2", "ErrorX2 NO BASE!?", 0);
	return NULL;
}
std::vector<std::size_t> AOBScan(std::string str_pattern) {
	std::vector<std::size_t> ret;
	HANDLE hProc = dbg.debuggeehProcess;

	ULONG_PTR dwStart = dbg.procBase;

	LPVOID lpHeader = malloc(0x1000);
	ReadProcessMemory(hProc, (LPCVOID)dwStart, lpHeader, 0x1000, NULL);

	DWORD delta = 0x1000;
	LPCVOID lpStart = 0; //0
	DWORD nSize = 0;// 0x548a000;

	PIMAGE_SECTION_HEADER SHcode = getCodeSection(lpHeader);
	if (SHcode) {
		nSize = SHcode->Misc.VirtualSize;
		delta = SHcode->VirtualAddress;
		lpStart = ((LPBYTE)dwStart + delta);
	}
	if (nSize) {
		
		LPVOID lpCodeSection = malloc(nSize);
		ReadProcessMemory(hProc, lpStart, lpCodeSection, nSize, NULL);

		//sprintf_s(szPrint, 124, "Size: %i / Start:%p / Base: %p", nSize, dwStart,lpStart);
		//MessageBoxA(0, szPrint, szPrint, 0);
		//
		auto res = find_pattern((const uint8_t*)lpCodeSection, nSize, pattern(str_pattern.c_str()));
		ret = res;
		for (UINT i = 0; i < ret.size(); i++) {
			ret[i] += delta;
		}

		free(lpCodeSection);
	}
	else {
		printf("bad .code section.\n");
	}
	free(lpHeader);


	return ret;
}
DWORD DoScan(std::string pattern, DWORD offset = 0, DWORD base_offset = 0, DWORD pre_base_offset = 0, DWORD rIndex = 0) {
	//ULONG_PTR dwBase = (DWORD_PTR)GetModuleHandleW(NULL);
	auto r = AOBScan(pattern);
	if (!r.size())
		return 0;
	//char msg[124];
	//sprintf_s(msg,124,"%s ret %i\n",pattern.c_str(),r.size() );
	//OutputDebugStringA(msg);
	DWORD ret = r[rIndex] + pre_base_offset;
	if (offset == 0) {
		return ret + base_offset;
	}
	DWORD dRead = Read<DWORD>((LPBYTE)dbg.procBase + ret + offset);
	ret = ret + dRead + base_offset;
	//ret = ret + *(DWORD*)(dwBase + ret + offset) + base_offset;
	return ret;
}

void ShowRev(FRev r,const char* szNamespace, bool bSingle = false) {

	printf("namespace %s {\n", szNamespace);
	printf("const DWORD ENCRYPT_PTR_OFFSET = 0x%X;\n", r.pEncrypt);
	printf("const DWORD REVERSED_ADDRESS = 0x%X;\n", r.pReverse);
	printf("const DWORD LAST_KEY_XOR = 0x%02X;\n", r.bXor);

	if (bSingle) {
		for (DWORD j = 0; j < 4; j++) {
			printf("const DWORD64 KEY_%i = 0x%p;\n", j, r.keys[0][j]);
		}
	}
	else {
		for (DWORD i = 0; i < 16; i++) {
			for (DWORD j = 0; j < 4; j++) {
				printf("const DWORD64 KEY_%i_%i = 0x%p;\n", i, j, r.keys[i][j]);
			}
			printf("\n");
		}
	}

	printf("}\n");
}

void Dump() {
	DWORD64 idxArray = 0;

	dbg.InitProcess();
	DWORD64 pBase = dbg.procBase;
	bool bGenKey = true;
	if (bGenKey) {
		dbg.SingleStep();
		bExcept = false;
		//aob scan
		//printf("//Bone Dump\n");
		DWORD64 pBoneScan = pBase + DoScan("56 57 48 83 EC ?? 80 BA 2C 0A 00 00 00 48 8B EA 65 4C 8B 04 25 58 00 00 00");
		DWORD64 pSetRdx = pBoneScan;
		//find lea rdx, ds:[0x00007FF796840000]
		while (Read<DWORD>(pSetRdx) != 0x840FC084)
			pSetRdx++;
		pSetRdx += 8;

		DWORD pEncrypt = 0;
		DWORD64 movsx = 0;
		uint64_t instructionPointer = 0x007FFFFFFF400000;
		ZydisDecodedInstruction instruction;
		DWORD64 pScan = pSetRdx + 7;
		//lets use zydis
		while (!movsx || !pEncrypt) {
			BYTE bRead[20];
			dbg.ReadTo(pScan, bRead, 20);
			bool goodDec = ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
				&decoder, bRead, 20,
				instructionPointer, &instruction));
			if (goodDec) {
				//look for movsx
				if (instruction.mnemonic == ZYDIS_MNEMONIC_MOVSX) {
					//printf("found %i\n", instruction.mnemonic);
					movsx = instruction.operands[1].mem.disp.value;
					idxArray = movsx;
					//printf("DWORD INDEX_ARRAY_OFFSET = 0x%08X;\n", movsx);
					//break;
				}
				else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
					if (instruction.operands[1].mem.disp.value > 0x100) {
						pEncrypt = pScan + 7 + instruction.operands[1].mem.disp.value - pBase;
						//printf("DWORD ENCRYPT_PTR_OFFSET = 0x%08X;\n", pEncrypt);
					}
				}
				pScan += instruction.length;
			}
		}

		//now get x and y
		//find ENCRYPT_PTR_OFFSET 
		//find INDEX_ARRAY_OFFSET  
		//find REVERSED_ADDRESS  
		//find BONE_BASE_POS ?????  

		DWORD64 pCmpJA = pSetRdx;
		while (Read<DWORD>(pCmpJA) != 0x0EF98348) pCmpJA++;
		printf("//pBoneBase: %p / %p / %p\n", pBoneScan, pSetRdx, pCmpJA);

		FRev fRev;
		fRev.pEncrypt = pEncrypt;

		for (int i = 0; i < 16; i++) {
			DumpFnc(fRev,i, pCmpJA, pSetRdx, i == 0);
		}
		ShowRev(fRev,"_0x150");

		//printf("//Entity Dump\n");
		DWORD64 pEntScan = pBase + DoScan("24 03 75 29") + 0x80;

		pEncrypt = 0;
		//lets use zydis
		pScan = pEntScan;
		while (!pEncrypt) {
			BYTE bRead[20];
			dbg.ReadTo(pScan, bRead, 20);
			bool goodDec = ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
				&decoder, bRead, 20,
				instructionPointer, &instruction));
			if (goodDec) {
				if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
					if (instruction.operands[1].mem.disp.value > 0x100) {

						pEncrypt = pScan + 7 + instruction.operands[1].mem.disp.value - pBase;
						//printf("DWORD ENCRYPT_PTR_OFFSET = 0x%08X;\n", pEncrypt);
						break;
					}
				}
				pScan += instruction.length;
			}
		}

		pCmpJA = pEntScan;
		while (Read<DWORD>(pCmpJA) != 0x0EF88348) pCmpJA++;
		printf("//pEntScan: %p / %p / %p\n", pEntScan, 0, pCmpJA);

		fRev.pEncrypt = pEncrypt;
		pCmpJA = pBase+0x242E059;
		for (int i = 0; i < 16; i++) {
			DumpFnc(fRev,i, pCmpJA, 0, i == 0);
		}
		ShowRev(fRev, "Entity_0x358");

		//CMD
		//DWORD64 pCmd = pBase + DoScan("4C 8B DC 41 56 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 49 89", 0, 0, 0, 3) + 0x1DF;
		DWORD64 pCmd = pBase + DoScan("4C 8B DC 41 56 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 49 89", 0, 0, 0, 3) + 0x1D6;
		//printf("//CMD Dump %p\n", pCmd);
		//DumpFnc(fRev,0, pCmd, 0, true);
		//ShowRev(fRev, "cmd", true);


		DWORD64 pClientInfo = pBase + DoScan("0F 29 74 24 20 0F 28 F3 81 FB FF 07 00 00")+0x14;

		printf("//clientnfo_t Dump %p\n", pClientInfo);
		pEncrypt = Read<DWORD>(pClientInfo+3)+pClientInfo+7-pBase;
		fRev.pEncrypt = pEncrypt;
		//printf("DWORD ENCRYPT_PTR_OFFSET = 0x%08X;\n", pEncrypt);
		DumpFnc(fRev,0, pClientInfo, 0, true,true);
		ShowRev(fRev, "_0x3580", true);
		//search for imul..
		
	}
	printf("#define INDEX_ARRAY_OFFSET 0x%08X\n", idxArray);
	printf("#define BONE_BASE_POS 0x%08X\n", Read<DWORD>(pBase + DoScan(("74 0e ?? ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 74 05 B8")) + 17));
	printf("#define clientinfo_t_size 0x%04X\n", Read<DWORD>(pBase + DoScan(("?? 03 ?? 0F 2F 37 76 6A")) - 4));
	printf("#define BASE_OFFSET 0x%04X\n", Read<DWORD>(pBase + DoScan(("48 8B 7C 24 40 48 85 C0 74 22")) - 4));
	//now offsets
	printf("#define NORECOIL_OFFSET  0x%08X\n", Read<DWORD>(pBase + DoScan(("0F 28 C2 0F 28 CA F3 0F 59 45 00 F3 AA F3 0F 11 45 00")) +0x2E));
	printf("#define NAME_ARRAY_OFFSET 0x%08X\n", DoScan(("4C 8D 44 24 20 EB 1A 48"), 3, 7, 7));

	auto dwCAM_PTR = DoScan(("F3 0F 11 89 C4 01 00 00 F3 0F 11 91 C8 01 00 00 C6 81 C0 01 00 00 01"), 3, 7, -7);
	printf("#define CAM_PTR 0x%08X\n", dwCAM_PTR);
	printf("#define DEFREF_PTR 0x%08X\n", DoScan(("48 85 C9 74 1B 8B 41 7C"), 3, 7, -7)); //veirfy plz
	printf("#define FunctionDisTribute 0x%08X\n", DoScan(("41 0F B7 84 50 00 88 13 00 66 39 41 02"), 3, 7, -7));
	printf("#define AboutVisibleFunction 0x%08X\n", DoScan(("F3 0F 11 ?? 1C 01 00 00 83 ?? 3C 01 00 00 03 48 89 ?? 88 00 00 00"),3,7,0x16));
	//printf("#define decrypt_key_for_bone_base 0x%08X\n", DoScan(("48 89 54 24 10 53 55 56 57 48 83 EC 38 80 BA 2C 0A 00 00 00 48 8B EA 65 4C 8B 04 25 58 00 00 00")));

	//DWORD64 pCheck = pBase + DoScan("84 C0 75 08 B0 01 48 83 C4 40 5B C3") - 0x20;
	DWORD64 pCheck = pBase + DoScan("84 C0 75 08 B0 01 48 83 C4 50 ?? C3") - 0x26;
	DWORD pOff = Read<DWORD>(pCheck + 2);
	if(pOff > 0x500) pOff = Read<BYTE>(pCheck + 5);
	printf("#define VALID_OFFSET 0x%04X //%p\n", pOff,pCheck);
	pOff = Read<DWORD>(pCheck + 12);
	if (pOff > 0x500) pOff = Read<BYTE>(pCheck + 12);
	printf("#define TYPE_OFFSET 0x%04X\n", pOff);

	//stance?
	//
	pCheck = pBase + DoScan("41 8B 54 24 0C 41 8B 4D 0C 3B CA 74 1E");
	pOff = Read<DWORD>(pCheck - 4);
	if (pOff > 0x100000)pOff = Read<BYTE>(pCheck - 1);
	printf("#define LOCAL_INDEX_OFFSET 0x%X\n", pOff);


}
int main() {

	// Initialize decoder context.
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);

	// Initialize formatter. Only required when you actually plan to
	// do instruction formatting ("disassembling"), like we do here.
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	printf("Hi!\n");

	//Dump();
	//printf("//===========================//\n");
	Dump();

	getchar();
	return 0;
}
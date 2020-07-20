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
			"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 18-07.exe"
			, NULL,
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
		printf("T[%i] P[%04X] Process launched and suspended. [%p]\n", debuggeethreadID, debuggeeprocessID, procBase);
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
	void Write(DWORD64 addr, T t) {
		size_t nRead;
		WriteProcessMemory(debuggeehProcess, (LPVOID)addr, &t, sizeof(T), &nRead);
	}
	BYTE setBreakPointAt(DWORD64 addr)
	{
		BYTE byte = Read<BYTE>(addr);
		//readDebuggeeMemory(addr, 1, &byte);

		Write<BYTE>(addr, 0xCC);//BYTE intInst = 0xCC;
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
			printf("//%p - access violation!!!\n", pInfo->ExceptionRecord.ExceptionAddress);
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
void Write(DWORD64 adr, T t) {
	WriteProcessMemory(dbg.debuggeehProcess, (LPBYTE)adr, &t, sizeof(T), NULL);
}
#include <inttypes.h>
#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")
ZydisDecoder decoder;

#include <vector>
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);


class CRegisterFrame {
public:
	static DWORD c_idx;
	DWORD idx;
	DWORD rva;
	CONTEXT ctx;
	CRegisterFrame(DWORD _rva, CONTEXT _ctx) : rva(_rva), ctx(_ctx) {
		idx = c_idx++;
	}
	CRegisterFrame(CONTEXT _ctx) : ctx(_ctx) {
		idx = c_idx++;
		rva = ctx.Rip - dbg.procBase;
	}
	ZydisDecodedInstruction* get_instruction() {
		// Initialize decoder context
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);


		static ZydisDecodedInstruction instruction;
		BYTE bRead[20];
		dbg.ReadTo(ctx.Rip, bRead, 20);

		if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
			&decoder, bRead, 20,
			ctx.Rip, &instruction))) {
			return &instruction;
		}
		return NULL;
	}
};
DWORD CRegisterFrame::c_idx = 0;


#include <unordered_map>
class CRegisterTracker {
public:
	std::vector<CRegisterFrame> frames;
	std::unordered_map<ZydisRegisters, std::string> register_alias;
	ZydisRegister mainReg = ZYDIS_REGISTER_NONE;
	ZydisRegister bswapHolderReg = ZYDIS_REGISTER_NONE;
	std::string get_alias(ZydisRegister r) {
		for (auto it : regTracker.register_alias)
		{
			if (it.first == r) {
				return it.second;
			}
		}
		return std::string();
	}
	std::string track(ZydisRegister r, DWORD idx = 0, bool bRecursive = false) {
		std::string ret;
		//check for alias..
		auto alias = get_alias(r);
		DWORD64 pRip = 0;

		//iter frames..
		for (auto it = frames.rbegin(); it != frames.rend(); ++it)
		{
			if (idx && it->idx >= idx) continue;
			else if (it == frames.rbegin()) continue; //skip first.. //loop till cur frame..


			auto inst = it->get_instruction();
			if (inst) {

				ZydisDecodedInstruction ic = *inst;
				inst = &ic;
				if (inst->operands[0].reg.value == r ||
					(inst->mnemonic == ZYDIS_MNEMONIC_BSWAP && ic.operands[1].mem.base == r)) {
					pRip = inst->instrAddress;
					char buf[32];
					//sprintf_s(buf, 32, "[0x%X]: ", it->rva);
					//ret = buf;

					if (inst->mnemonic == ZYDIS_MNEMONIC_BSWAP) {
						ret = "BSWAP";
					}
					else if (inst->mnemonic == ZYDIS_MNEMONIC_MOV) {
						if (inst->operands[0].reg.value == mainReg) { //overwrite main reg?
							ret = track(inst->operands[1].reg.value, it->idx);
						}
						else {
							//check if its register, if so check alias
							if (inst->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
								ret = track(inst->operands[1].mem.base, it->idx);
							} else if (inst->operands[1].reg.value == ZYDIS_REGISTER_NONE) {
								sprintf_s(buf, 32, "0x%p", inst->operands[1].imm.value);

								ret += buf;
							}
							else {
								//look for alias..
								//track this
								auto t = std::string();// (inst->operands[1].reg.value, it->idx);
								if (t.empty()) {

									auto alias = get_alias(inst->operands[1].reg.value);
									if (!alias.empty()) ret = alias;
									else ret = ZydisRegisterGetString(inst->operands[1].reg.value);
								}
								else {
									ret = t;
								}

							}
						}
					}
					else if (inst->mnemonic == ZYDIS_MNEMONIC_IMUL) {
						if (inst->operandCount == 4) {
							auto alias = get_alias(inst->operands[1].reg.value);
							if (alias.empty()) alias = ZydisRegisterGetString(inst->operands[1].reg.value);
							sprintf_s(buf, 32, "(%s * %i)", alias.c_str(), inst->operands[2].imm.value);
							ret += buf;
						}
						else {
							auto _alias = track(inst->operands[1].reg.value, it->idx);
							if (_alias.empty()) _alias = ZydisRegisterGetString(inst->operands[1].reg.value);

							auto r0_track = track(inst->operands[0].reg.value, it->idx);
							//imul reg 0
							ret += "(";
							ret += r0_track;
							ret += " * ";
							ret += _alias;
							ret += ")";
						}
					}
					else if (inst->mnemonic == ZYDIS_MNEMONIC_XOR) {
						auto r0_track = track(inst->operands[0].reg.value, it->idx);
						auto r1_track = track(inst->operands[1].reg.value, it->idx);
						ret += "(" + r0_track + " ^ " + r1_track + ")";
					}
					else if (inst->mnemonic == ZYDIS_MNEMONIC_ADD) {
						auto r0_track = track(inst->operands[0].reg.value, it->idx);
						auto r1_track = track(inst->operands[1].reg.value, it->idx);
						ret += "(" + r0_track + " + " + r1_track + ")";
					}
					else if (inst->mnemonic == ZYDIS_MNEMONIC_SUB) {
						auto r0_track = track(inst->operands[0].reg.value, it->idx);
						auto r1_track = track(inst->operands[1].reg.value, it->idx);
						ret += "(" + r0_track + " - " + r1_track + ")";
					}
					else if (inst->mnemonic == ZYDIS_MNEMONIC_SHR) {
						auto r0_track = track(inst->operands[0].reg.value, it->idx);
						//solve operand 0
						sprintf_s(buf, 32, "(%s >> 0x%08X)", r0_track.c_str(), inst->operands[1].imm.value);
						ret += buf;
					}
					break;
				}
			}

		}

		if (ret.empty()) {
			if(!alias.empty()) return alias;
			//return register
			return ZydisRegisterGetString(r);
		}
		//if (!ret.empty()) printf("%i track: %s / %p\n",idx, ret.c_str(),pRip);
		return ret;
	}
} regTracker;


std::string resolve_op(ZydisDecodedInstruction inst) {
	ZydisRegister r1 = inst.operands[0].reg.value;
	ZydisRegister r2 = inst.operands[1].reg.value;
	bool valid = false;
	std::string ret;


	std::string s1 = ZydisRegisterGetString(r1);
	std::string alias = regTracker.get_alias(r1);
	if (!alias.empty()) {
		valid = true;
		s1 = alias;
	}

	ret = s1;
	switch (inst.mnemonic) {
	case ZYDIS_MNEMONIC_MOV:
		ret += +" = ";
		break;
	case ZYDIS_MNEMONIC_ADD:
		ret += +" += ";
		break;
	case ZYDIS_MNEMONIC_SUB:
		ret += +" -= ";
		break;
	case ZYDIS_MNEMONIC_XOR:
		ret += +" ^= ";
		break;
	case ZYDIS_MNEMONIC_IMUL:
		ret += +" *= ";
		break;
	default:
		ret += " ??? ";
		break;
	}
	bool is_alias = r2 == ZYDIS_REGISTER_NONE;
	std::string s2 = ZydisRegisterGetString(r2);
	alias = regTracker.get_alias(r2);
	if (!alias.empty()) {
		valid = true;
		s2 = alias;
		is_alias = true;
	}

	if (valid && inst.mnemonic == ZYDIS_MNEMONIC_MOV && r2 == ZYDIS_REGISTER_NONE) {
		auto r_mem = inst.operands[1].mem.base;
		auto disp = inst.operands[1].mem.disp.value;
		//printf("opC: %i / %i\n", inst.operandCount, inst.operands[0].reg.value);

		std::string mem_reg = regTracker.track(r_mem);
		char buf[32];
		sprintf_s(buf, 32, "[%s + 0x%02X]: ", mem_reg.c_str(), disp);
		s2 = buf;
		//__debugbreak();
	}

	if (inst.mnemonic == ZYDIS_MNEMONIC_IMUL && inst.operandCount == 4) {
		//get reg3
		auto alias = regTracker.get_alias(inst.operands[1].reg.value);
		if (alias.empty()) alias = ZydisRegisterGetString(inst.operands[1].reg.value);
		char buf[32];
		sprintf_s(buf, 32, "%s * %i", alias.c_str(), inst.operands[2].imm.value);
		s2 = buf;
	}


	ret += s2;

	if (!is_alias) {
		//now resolve s2
		ret += " //(" + regTracker.track(r2) + ")";
	}


	return valid ? ret : std::string();
}

void StepOver() {
	static ZydisDecodedInstruction instruction;
	CONTEXT c = dbg.GetContext();
	regTracker.frames.push_back(c);
	if (bExcept) {
		//skip?
		printf("GOT EXCEPT!\n");
		c.Rip += instruction.length;
		dbg.SetContext(&c);
		bExcept = false;
		return;//
	}
	dbg.SingleStep();
	// Format & print the binary instruction structure to human readable format

	// Initialize decoder context
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	// Initialize formatter. Only required when you actually plan to do instruction
	// formatting ("disassembling"), like we do here
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	BYTE bRead[20];
	dbg.ReadTo(c.Rip, bRead, 20);

	if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, bRead, 20,
		c.Rip, &instruction))) {

		std::string comment = resolve_op(instruction);
		//now we add comments :D
		//see if we can identify alias
		if (comment.empty())return;
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer));
		printf("[0x%X]: %s", c.Rip - dbg.procBase, buffer);
		if (!comment.empty()) {
			bool bComment = instruction.operands[0].reg.value == regTracker.mainReg;
			SetConsoleTextAttribute(hConsole, bComment ? 12 : 11);//blue or red
			printf(" //%s", comment.c_str());
			SetConsoleTextAttribute(hConsole, 7);//blue or red
		}
		printf("\n");
	}
	//print
}

void DumpDecFnc() {
	DWORD64 pSetReg = dbg.procBase + 0x1470565;// +DoScan("0F B6 4C 24 40 48 C1 C9 0C 83 E1 0F 48 83 F9 0E") + 0x0C;
	printf("//==================== DUMP ClientInfo_Base! =======================//\n");
	//DumpDecFnc2(pSetReg);
	//start stepping..

	CONTEXT c = dbg.GetContext();
	c.Rip = pSetReg;
	c.Rcx = dbg.procBase;
	c.Rax = 0; //fnc index
	dbg.SetContext(&c);

	regTracker.mainReg = ZYDIS_REGISTER_RDX;
	regTracker.register_alias[ZYDIS_REGISTER_RDX] = "ret_val";
	regTracker.register_alias[ZYDIS_REGISTER_R11] = "not_peb";
	//regTracker.register_alias[ZYDIS_REGISTER_R11] = "bswap_val";

	bool bFirst = true;
	while (1) {
		if (bFirst || GetAsyncKeyState(VK_F3) & 1) {
			bFirst = false;
			//step forward
			for (DWORD i = 0; i < 156; i++) {
				StepOver();
			}
			//solve rax
			auto r = regTracker.track(regTracker.mainReg, CRegisterFrame::c_idx);
			printf("FINAL_DEC: %s\n", r.c_str());
		}
		Sleep(100);
	}
}
#define MAX_PROCESSES 1024

#include <vector>
#undef UNICODE
#include <TlHelp32.h>
DWORD nMinThreads = 0;
static std::vector<uint64_t> GetProcessIdsByName(std::string name)
{
	std::vector<uint64_t> res;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snap) throw std::exception("CreateToolhelp32Snapshot failed");
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);
	if (!Process32First(snap, &entry)) throw std::exception("Process32First failed");
	do
	{
		if (!_stricmp(entry.szExeFile, name.c_str()) && (nMinThreads == 0 || (entry.cntThreads > nMinThreads)))
		{
			res.push_back(entry.th32ProcessID);
		}
	} while (Process32Next(snap, &entry));
	CloseHandle(snap);
	return res;
}
void LaunchMW() {

	STARTUPINFOA startupinfo = { 0 };
	startupinfo.cb = sizeof(startupinfo);
	PROCESS_INFORMATION processinfo = { 0 };
	unsigned int creationflags = 0;

	if (CreateProcessA(
		"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare.exe"
		, NULL,
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
}
void Dump() {
	DWORD64 idxArray = 0;

	//attach process:
	auto procs = GetProcessIdsByName("modernwarfare.exe");
	DWORD pid = procs.size() ? procs[0]:0;
	printf("target proc: %i\n", pid);
	if (pid == 0) {
		//launch process and wait..
		LaunchMW();
		Sleep(2000);
		procs = GetProcessIdsByName("modernwarfare.exe");
		pid = procs.size() ? procs[0] : 0;
	}
	if (pid) {

		auto r = dbg.AttachProcess(pid);
		dbg.SingleStep();

		CONTEXT c = dbg.GetContext();
		c.Rip = dbg.procBase + 0x1470565;
		dbg.SetContext(&c);
		//suspend process.
		DumpDecFnc();

		//dbg.InitProcess();
		DWORD64 pBase = dbg.procBase;
		/*bool bGenKey = true;
		if (bGenKey) {
			dbg.SingleStep();
			bExcept = false;
			DumpDecFnc();
		}*/

		//printf("%p dettach!\n",pBase);
		DebugActiveProcessStop(pid);
		TerminateProcess(dbg.debuggeehProcess,0);
		getchar();
	}
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

	Dump();

	getchar();
	return 0;
}
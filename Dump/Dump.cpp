// Dump.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
using namespace std;
//
int _tmain(int argc, _TCHAR* argv[])
{
	ofstream outfile;
	unsigned int DataBufferSize = 0;
	unsigned char* DataBuffer = NULL;
	string filename = "ABCD";
	unsigned char* SearchBuffer = NULL;
	// PCMP
	char* PCMP_sig = "PCMP";
	// ACPI
	unsigned int EnumSize = 0;
	unsigned char* EnumBuffer = NULL;
	// cert
	char* begin = "<?xml version=\"1.0\" encoding=\"utf-8\"?><r:license";
	char* cert = "<r:title>OEM Certificate</r:title>";
	char* end = "</r:license>";
	char* licdatab = "kgAAAAAAA";
	char* licdatae = "</sl:data>";
	unsigned char* sldata = NULL;
	unsigned char* decsldata = NULL;
	unsigned int sldatasize = 0;
	unsigned int sldatabegin = 0;
	unsigned int sldataend = 0;
	unsigned int certbegin = 0;
	unsigned int certend = 0;
	unsigned int oem = 0;
	unsigned int certnum = 0;
	string TokensFile = "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\SoftwareProtectionPlatform\\tokens.dat";
	// product key
	LSTATUS Status = 0;
	HKEY KeyHandle = NULL;
	unsigned char Chars[] = "BCDFGHJKMPQRTVWXY2346789";
	unsigned char* KeyOutput = NULL;
	unsigned char* buffer = NULL;
	const int KeyOffset = 52;
	int KeyIndex = 24;
	size_t Last = 0;
	int isWin8 = 0;
	// types
	typedef struct {
		CHAR Sig[4];
		WORD Length;
		BYTE Revision;
		BYTE Checksum;
		CHAR OEMID[8];
		CHAR PID[12];
		DWORD OEMPointer;
		WORD OEMLength;
		WORD EntryCount;
		DWORD APICAddress;
		WORD ExTableLen;
		BYTE ExTableChecksum;
		BYTE Reserved;
	} PCMP_header_t;
	//
	// dump low mem
	//
	try {
		EnumSize = EnumSystemFirmwareTables('FIRM', NULL, NULL);
		EnumBuffer = new unsigned char[EnumSize];
		EnumSize = EnumSystemFirmwareTables('FIRM', EnumBuffer, EnumSize);
		int count = 0;
		if(EnumSize != 0) {
			for (unsigned int i = 0; i < EnumSize; i += 4) {
				DataBufferSize = GetSystemFirmwareTable('FIRM', *(DWORD*)&EnumBuffer[i], NULL, NULL);
				DataBuffer = new unsigned char[DataBufferSize];
				DataBufferSize = GetSystemFirmwareTable('FIRM', *(DWORD*)&EnumBuffer[i], DataBuffer, DataBufferSize);
				if (DataBufferSize != 0) {
					count++;
					char a[5] = {};
					_itoa_s(count, a, 10);
					filename = "lowmem.";
					filename += a;
					filename += ".bin";
					outfile.open(filename, ios_base::binary);
					if (outfile.is_open()) {
						outfile.write((char*) DataBuffer,DataBufferSize);
						outfile.close();
					}
					// search DataBuffer for "PCMP"
					SearchBuffer = new unsigned char[sizeof(PCMP_header_t)];
					for (unsigned int j = 0; j < (DataBufferSize - sizeof(PCMP_header_t)); j++) {
						memcpy(SearchBuffer, (void*) &DataBuffer[j], sizeof(PCMP_header_t));
						if (memcmp(SearchBuffer, PCMP_sig, 4) == 0) {
							// found "PCMP" dump to file
							PCMP_header_t *PCMP_header = (PCMP_header_t*) (DataBuffer + j);
							outfile.open("PCMP.bin", ios_base::binary);
							if (outfile.is_open()) {
								outfile.write((char*) DataBuffer + j, PCMP_header->Length);
								outfile.close();
							}
						}
					}
					delete[] SearchBuffer;
				}
				delete[] DataBuffer;
			}
		}
		delete[] EnumBuffer;
		// dump ACPI table's to file.
		EnumSize = EnumSystemFirmwareTables('ACPI', NULL, NULL);
		EnumBuffer = new unsigned char[EnumSize];
		EnumSize = EnumSystemFirmwareTables('ACPI', EnumBuffer, EnumSize);
		if(EnumSize != 0) {
			for (unsigned int i = 0; i < EnumSize; i += 4) {
				DataBufferSize = GetSystemFirmwareTable('ACPI', *(DWORD*)&EnumBuffer[i], NULL, NULL);
				DataBuffer = new unsigned char[DataBufferSize];
				DataBufferSize = GetSystemFirmwareTable('ACPI', *(DWORD*)&EnumBuffer[i], DataBuffer, DataBufferSize);
				if (DataBufferSize != 0) {
					char* tmp = (char*)(DWORD*)&EnumBuffer[i];
					char a[5] = {};
					memcpy(a, tmp, 4);
					filename = a;
					filename += ".bin";
					outfile.open(filename, ios_base::binary);
					if (outfile.is_open()) {
						outfile.write((char*) DataBuffer,DataBufferSize);
						outfile.close();
					}
				}
				delete[] DataBuffer;
			}
		}
		delete[] EnumBuffer;
		// dump DSDT to file.
		DataBufferSize = GetSystemFirmwareTable('ACPI', 'TDSD', NULL, NULL);
		DataBuffer = new unsigned char[DataBufferSize];
		DataBufferSize = GetSystemFirmwareTable('ACPI', 'TDSD', DataBuffer, DataBufferSize);
		if(DataBufferSize != 0) {
			outfile.open("DSDT.bin", ios_base::binary);
			if (outfile.is_open()) {
				outfile.write((char*) DataBuffer, DataBufferSize);
				outfile.close();
			}
		}
		delete[] DataBuffer;
		// dump RSDT to file.
		DataBufferSize = GetSystemFirmwareTable('ACPI', 'TDSR', NULL, NULL);
		DataBuffer = new unsigned char[DataBufferSize];
		DataBufferSize = GetSystemFirmwareTable('ACPI', 'TDSR', DataBuffer, DataBufferSize);
		if(DataBufferSize != 0) {
			outfile.open("RSDT.bin", ios_base::binary);
			if (outfile.is_open()) {
				outfile.write((char*) DataBuffer, DataBufferSize);
				outfile.close();
			}
		}
		else {
			//dump XSDT to file.
			DataBufferSize = GetSystemFirmwareTable('ACPI', 'TDSX', NULL, NULL);
			DataBuffer = new unsigned char[DataBufferSize];
			DataBufferSize = GetSystemFirmwareTable('ACPI', 'TDSX', DataBuffer, DataBufferSize);
			if(DataBufferSize != 0) {
				outfile.open("XSDT.bin", ios_base::binary);
				if (outfile.is_open()) {
					outfile.write((char*) DataBuffer, DataBufferSize);
					outfile.close();
				}
			}
		}
		delete[] DataBuffer;
		// dump SMBIOS to file.
		DataBufferSize = GetSystemFirmwareTable('RSMB', NULL, NULL, NULL);
		DataBuffer = new unsigned char[DataBufferSize];
		DataBufferSize = GetSystemFirmwareTable('RSMB', NULL, DataBuffer, DataBufferSize);
		if(DataBufferSize != 0) {
			outfile.open("SMBIOS.bin", ios_base::binary);
			if (outfile.is_open()) {
				outfile.write((char*) DataBuffer, DataBufferSize);
				outfile.close();
			}
		}
		delete[] DataBuffer;
		// extract OEM certificate(s) from tokens.dat.
		ifstream tokens(TokensFile, ios_base::binary);
		if (!tokens.is_open()) {
			goto getpkey;
		}
		tokens.seekg(0, ios_base::end);
		DataBufferSize = (unsigned int) tokens.tellg();
		tokens.seekg(0, ios_base::beg);
		DataBuffer = new unsigned char[DataBufferSize];
		tokens.read((char*) DataBuffer, DataBufferSize);
start:
		// find string "OEM Certificate".
		SearchBuffer = new unsigned char[34];
		for (unsigned int i = oem; i < (DataBufferSize - 34); i++) {
			memcpy(SearchBuffer, (void*) &DataBuffer[i], 34);
			if (memcmp(SearchBuffer, cert, 34) == 0) {
				oem = i;
				break;
			}
			if (i >= (DataBufferSize - 35)) {
				goto end;
			}
		}
		// search backwards from "OEM Certificate" to beginning of certificate.
		SearchBuffer = new unsigned char[48];
		for (unsigned int i = oem; i > (oem - 1000); i--) {
			memcpy(SearchBuffer, (void*) &DataBuffer[i], 48);
			if (memcmp(SearchBuffer, begin, 48) == 0) {
				certbegin = i;
				break;
			}
		}
		// search forwards from "OEM Certificate" to end of certificate.
		SearchBuffer = new unsigned char[12];
		for (unsigned int i = oem; i < (oem + 3000); i++) {
			memcpy(SearchBuffer, (void*) &DataBuffer[i], 12);
			if (memcmp(SearchBuffer, end, 12) == 0) {
				certend = i + 12;
				oem = i;
				break;
			}
		}
		// search for beginning of sl:data in certificate.
		SearchBuffer = new unsigned char[9];
		for (unsigned int i = certbegin; i < certend; i++) {
			memcpy(SearchBuffer, (void*) &DataBuffer[i], 9);
			if (memcmp(SearchBuffer, licdatab, 9) == 0) {
				sldatabegin = i;
				break;
			}
		}
		// search for end of sl:data in certificate.
		SearchBuffer = new unsigned char[10];
		for (unsigned int i = sldatabegin; i < certend; i++) {
			memcpy(SearchBuffer, (void*) &DataBuffer[i], 10);
			if (memcmp(SearchBuffer, licdatae, 10) == 0) {
				sldataend = i;
				break;
			}
		}
		// decode base64 sl:data.
		sldatasize = sldataend-sldatabegin;
		sldata = new unsigned char[sldatasize];
		decsldata = new unsigned char[sldatasize];
		memcpy(sldata, DataBuffer + sldatabegin, sldatasize);
		Base64Decode((LPSTR)sldata, (int)sldatasize, decsldata, (int *)&sldatasize);
		delete[] sldata;
		// build certificate file name.
		char tmpstr[21] = {};
		memcpy(tmpstr, decsldata + 8, 6);
		delete[] decsldata;
		filename = tmpstr;
		filename.erase(filename.find_last_not_of(" \t\n\r\f\v")+1); 
		filename += ".";
		_itoa_s((int)certnum, tmpstr, 10);
		filename += tmpstr;
		filename += ".xrm-ms";
		// write certificate to file.
		outfile.open(filename, ios_base::binary);
		if (outfile.is_open()) {
			outfile.write((char*) (DataBuffer + certbegin),(certend - certbegin)); 
			outfile.close();
		}
		if (oem < DataBufferSize) {
			certnum++;
			goto start;
		}
end:
		delete[] SearchBuffer;
		delete[] DataBuffer;
getpkey:
		// get product key from registry.
		Status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"),
			0,
			KEY_READ|KEY_WOW64_64KEY,
			&KeyHandle );

		if (Status != ERROR_SUCCESS)
			return Status;

		Status = RegQueryValueEx(
			KeyHandle,
			TEXT("DigitalProductId"),
			NULL,
			NULL,
			NULL,
			(LPDWORD) &DataBufferSize );

		if (Status != ERROR_SUCCESS)
			return Status;

		DataBuffer = new unsigned char[DataBufferSize];

		Status = RegQueryValueEx(
			KeyHandle,
			TEXT("DigitalProductId"),
			NULL,
			NULL,
			DataBuffer,
			(LPDWORD) &DataBufferSize );

		if (Status != ERROR_SUCCESS)
			return Status;

		RegCloseKey(KeyHandle);
		// save the raw key data to file.
		filename = "DigitalProductId.bin";
		outfile.open(filename, ios_base::binary);
		if (outfile.is_open()) {
			outfile.write((char*) DataBuffer, DataBufferSize);
			outfile.close();
		}
		// decode product key.
		isWin8 = (DataBuffer[66] >> 3) & 1;
		DataBuffer[66] = (unsigned char)((DataBuffer[66] & 0xF7) | ((isWin8 & 2) << 2));
		KeyOutput = new unsigned char[25];
		do {
			size_t Cur = 0;
			int X = 14;
			do {
				Cur = Cur << 8;
				Cur = DataBuffer[X + KeyOffset] + Cur;
				DataBuffer[X + KeyOffset] = (unsigned char)(Cur / 24);
				Cur %= 24;
				X--;
			} while (X >= 0);
			KeyIndex--;
			KeyOutput[KeyIndex + 1] = Chars[Cur];
			Last = Cur;
		} while (KeyIndex >= 0);
		if (isWin8) {
			buffer = new unsigned char[25];
			memcpy(buffer, KeyOutput + 1, Last);
			buffer[Last] = 'N';
			memcpy(buffer + Last + 1, KeyOutput + Last + 1, 25 - Last - 1);
			memcpy(KeyOutput, buffer, 25);
			delete[] buffer;
		}
		delete[] DataBuffer;
		int j = 0;
		DataBuffer = new unsigned char[29];
		for (int i = 0; i < 29; i++) {
			if (i == 5 || i == 11 || i == 17 || i == 23) {
				DataBuffer[i] = '-';
				i++;
			}
			DataBuffer[i] = KeyOutput[j];
			j++;
		}
		delete[] KeyOutput;
		// write product key to file.
		filename = "pkey.txt";
		outfile.open(filename, ios_base::binary);
		if (outfile.is_open()) {
			outfile.write((char*) DataBuffer, 29);
			outfile.close();
		}
		delete[] DataBuffer;
		return 0;
	}
	catch (bad_alloc) {
		if(NULL != SearchBuffer) {delete[] SearchBuffer;}
		if(NULL != DataBuffer) {delete[] DataBuffer;}
		if(NULL != EnumBuffer) {delete[] EnumBuffer;}
		if(NULL != KeyOutput) {delete[] KeyOutput;}
		if(NULL != buffer) {delete[] buffer;}
		if(NULL != sldata) {delete[] sldata;}
		if(NULL != decsldata) {delete[] decsldata;}
		return 1;
	}
}
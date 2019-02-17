## Even more hacked together by @JohnLaTwC, Aug 2018

## This script attempts to decode encoded powershell commands.  
##   REQUIREMENTS: This script uses vivisect for PE parsing and dissasembly: https://github.com/vivisect/vivisect. Set the PYTHONPATH as appropriate.
## e.g. set pythonpath=C:\vivisect-master\vivisect-master

import sys
import re
import argparse
import string

MAX_DISTANCE_FROM_KEYWORD = 100

szDbPath = None
fDbLoaded = False
fVerbose = False
fResolveAPIs = False
APIDict = {}
dis = None

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def hashapi(sz):
    val = 0
    for a in sz:
        val = ror(val, 0xd, 32)
        val = val + ord(a)
    return val

def blockhash(szDll, szAPI):
    from array import array
    sz = unicode(szDll.upper() + '\0')
    szEncDll = sz.encode("utf-16")
    szEncAPI = szAPI.encode("ascii") + '\0'
    
    iDll = hashapi(szEncDll[2:])
    iAPI = hashapi(szEncAPI)
    return 0x0000FFFFFFFF & (iDll+iAPI)


## This function makes the script Windows specific. It expect Windows binaries and uses them
## to build up a dictionary of API hashes.  One could fix this by doing this step on a 
## Windows PC and then storing the API hashes in file
## Sept 2017: support the ability to load from a DB
def PopulateExports(APIDict, szDll):
    global fVerbose
    from PE import PE
    import os
    fd = open(os.environ['SYSTEMROOT']+ '\\System32\\' +  szDll, 'rb')
    pe = PE(fd)
    for exp in pe.getExports():
        szAPI = exp[2]
        szHash = "0x%08x"%(blockhash(szDll, szAPI))
        APIDict[szHash] =  szDll + "!" + szAPI
        if (fVerbose):
            print("INSERT INTO APIs (module, api,hashvalue) VALUES('%s','%s','%s')" % (szDll, szAPI, szHash))

##  example:
##  0x00000000 b9c7060000       mov ecx,1735
##  0x00000005 e8ffffffff       call 0x00000009
##  0x0000000a c15e304c         rcr dword [esi + 48],76
##  0x0000000e 0e               push cs
##  0x0000000f 07               pop es
##  0x00000010 e2fa             loop 0x0000000c
##  0x00000012 b8b7050405       mov eax,0x050405b7
def decode_call_to_self(d, all_instr_list):
    ## verify some bytes first
    import array
    sd = array.array('B', d)
    szd = None

    #look for mov and call to self after a min number of instructions
    if len(all_instr_list) < 10:
        return None

    fFoundMov = False
    fFoundCounter = False
    fFoundCallToSelf = False
    iLen = 0
    iCallOffset = 0
    szMsg = 'No decoder found'
    for i in range(0, 2):
        instr_lst = all_instr_list[i]
        szInsBytes = instr_lst[1]
        szIns = instr_lst[2]
        offset = instr_lst[3]
        # e8ffffffff       call 0x00000009
        if szInsBytes == "e8ffffffff":
            fFoundCallToSelf = True
            iCallOffset = offset + 5
        # mov ecx,1735
        if szIns.startswith('mov ') and szIns.find('ecx,') > 0:
            fFoundCounter = True
            iLen = int(szIns.split(',')[1])
    if (fFoundCallToSelf and fFoundCounter and iLen > 0):
        szMsg = "Found call_to_self shellcode --> len = %d, decode offset= %d" % (iLen, iCallOffset)
        szd = []
        for i in range(0,iCallOffset):
            szd.append(chr(sd[i]))
        szd.append(chr(sd[iCallOffset - 1]))
        for i in range(iCallOffset,len(sd)-iCallOffset):
            szd.append(chr(sd[i]))
        return [''.join(szd), iLen, 0, iCallOffset, szMsg]

    return [None, 0, 0, 0, szMsg]

##  Example shellcode
##  0x00000000 dbd3             fcmovnbe st0,st3 
##  0x00000002 be1dd3f6b2       mov esi,0xb2f6d31d 
##  0x00000007 d97424f4         fnstenv  [esp - 12] 
##  0x0000000b 5a               pop edx 
##  0x0000000c 33c9             xor ecx,ecx 
##  0x0000000e b16e             mov cl,110 
##  0x00000010 83c204           add edx,4 
##  0x00000013 317214           xor dword [edx + 20],esi 
##  0x00000016 037209           add esi,dword [edx + 9] 
def decode_shikata_ga_nai(d, all_instr_list):
    global dis
    ## verify some bytes first
    import array
    sd = array.array('B', d)
    szd = None

    #look for floating point instr, fnstenv, and mov in first few instr
    if len(all_instr_list) < 10:
        return None

    fFoundFnstenv = False
    fFoundFloatingPtInstr = False
    fFoundMov = False
    fFoundCounter = False
    fFoundXor = False
    iLen = 0
    key = 0
    origkey = 0
    szMsg = 'No decoder found'
    iXorOffset = 0
    iXorAdjust = 0
    iFPOpOffset = 0
    for i in range(0, 10):
        instr_lst = all_instr_list[i]
        szIns = instr_lst[2]
        offset = instr_lst[3]
        # fnstenv  [esp - 12] 
        if szIns.startswith('fnstenv'):
            fFoundFnstenv = True
        #fxch st0,st6 
        if not fFoundFloatingPtInstr and not szIns.startswith('fnstenv') and szIns.startswith('f'):
            fFoundFloatingPtInstr = True
            iFPOpOffset = offset
        #xor dword [edx + 24],eax 
        if szIns.startswith('sub ') and szIns.endswith('0xfffffffc'):
            iXorAdjust = -4
        if szIns.startswith('xor dword ['):
            fFoundXor = True
            ## iXorAdjust needed for dd69c50d45ce297e203e353ece03b0ef47feb021b78298ac0eeb8e9c4f9f14a9
            ## 0x00000000 dbca             fcmovne st0,st2
            ## 0x00000002 d97424f4         fnstenv  [esp - 12]
            ## ...
            ## 0x0000000b 58               pop eax
            ## ...
            ## ...
            ## 0x00000010 83e8fc           sub eax,0xfffffffc
            ## 0x00000013 317016           xor dword [eax + 22],esi
            ## ...

            iXorOffset = int((szIns.split('+')[1]).split(']')[0]) + iXorAdjust 
            #find key operation. e.g. add esi,dword [eax + 14]
            for j in range(1,3):
                keyop_instr_lst = all_instr_list[i+j]
                szKeyOpIns = keyop_instr_lst[2]
                if szKeyOpIns.startswith('add e'):
                    szKeyOp = szKeyOpIns.split(' ')[0]
                    istart = keyop_instr_lst[3]
                    break
        # mov eax,0x4193fabc 
        if szIns.startswith('mov ') and szIns.find('0x') > 0 and not fFoundMov:
            fFoundMov = True
            k1 = sd[offset + 0x1]
            k2 = sd[offset + 0x2]
            k3 = sd[offset + 0x3]
            k4 = sd[offset + 0x4]
            origkey = key = k1 | (k2 << 8) | (k3 << 16)| (k4 << 24)
        # mov cl,110
        if szIns.startswith('mov ') and szIns.find('cl,') > 0:
            fFoundCounter = True
            iLen = int(szIns.split(',')[1])
    if (fFoundMov and fFoundFloatingPtInstr and fFoundFnstenv and fFoundCounter and iLen > 0):

        next_key_operation = d[istart: istart+3]
        
        szd = []
        for i in range(0,iXorOffset + iFPOpOffset):
            szd.append(chr(sd[i]))

        for i in range(iXorOffset + iFPOpOffset,len(sd)-(iXorOffset + iFPOpOffset), 4):
            szd.append(chr(k1 ^ sd[i]))
            szd.append(chr(k2 ^ sd[i+1]))
            szd.append(chr(k3 ^ sd[i+2]))
            szd.append(chr(k4 ^ sd[i+3]))
            data = k1^sd[i] | ((k2^sd[i+1]) << 8) | ((k3^sd[i+2]) << 16) | ((k4^sd[i+3]) << 24)

            #update the key based on the shikata rules
            if szKeyOp == "add":
                key = (key + data) & 0x00000000FFFFFFFF
            else:
                key = (key + data) & 0x00000000FFFFFFFF
                pass # error case

            k1 = 0x000000FF & key
            k2 = (0x0000FF00 & key) >> 8
            k3 = (0x00FF0000 & key) >> 16
            k4 = (0xFF000000 & key) >> 24

        szd = ''.join(szd)

        op = dis.disasm(szd, istart, istart)
        szIns = repr(op).lower()
        szKeyOp = szIns.split(' ')[0]
        # szOffsetDirection = szIns.split(' ')[3]
        # cOffset = int((szIns.split(' ')[4]).split(']')[0])
        szMsg = "Found shikata_ga_nai shellcode --> len = %d, key = 0x%x, decode offset= %d, fpop offset = %d, keyop= %s, istart=0x%x, '%s'" % (iLen, origkey, iXorOffset, iFPOpOffset, szKeyOp, istart, szIns)
    else:
        pass
    return [szd, iLen, key, iXorOffset, szMsg]

def process_instructions_impl(d, offset, va):
    global dis
    instr_list = []
    all_instr_list = []
    final_offset_msg= ''
    while offset < len(d):
        op = None
        try:
            op = dis.disasm(d, offset, va+offset)
            szIns = repr(op).lower()
            instr_lst = ['0x%.8x' % (va+offset),
                         '%s' % str(d[offset:offset+len(op)].encode('hex')),
                         szIns,
                         offset ]
            all_instr_list.append(instr_lst)
            offset += len(op)
        except Exception as e1: 
            final_offset_msg = 'Decode error at offset 0x%x' % offset
            break
    return [all_instr_list, final_offset_msg]

def process_instructions(d):
    global dis
    from envi.archs.i386 import i386Disasm 
    if dis is None:
        dis = i386Disasm()
    return process_instructions_impl(d,0,0)

def prepareAPIs():
    global APIDict
    global szDbPath
    global fDbLoaded

    ## if APIs are being loaded from a DB, then do that now
    if (szDbPath is not None and not fDbLoaded):
        import sqlite3
        db = sqlite3.connect(szDbPath)
        cursor = db.cursor()
        cursor.execute('''SELECT module, api, hashvalue FROM APIs''')
        all_rows = cursor.fetchall()
        for row in all_rows:
            szHash = row[2]
            szDll = row[0]
            szAPI = row[1]
            APIDict[szHash] =  szDll + "!" + szAPI
        db.close()
        fDbLoaded = True
    else:
        PopulateExports(APIDict, 'kernel32.dll')
        PopulateExports(APIDict, 'ws2_32.dll')
        PopulateExports(APIDict, 'ole32.dll')
        PopulateExports(APIDict, 'ntdll.dll')
        PopulateExports(APIDict, 'advapi32.dll')
        PopulateExports(APIDict, 'urlmon.dll')
        PopulateExports(APIDict, 'winhttp.dll')
        PopulateExports(APIDict, 'wininet.dll')

def dumpShellcode(d):
    global fResolveAPIs
    global APIDict
    szOut = ''
    if fResolveAPIs and len(APIDict) == 0:
        prepareAPIs()
        ## for szKey in APIDict.keys():
        ##      print ("%s  %s" % (szKey, APIDict[szKey]))

    # set pythonpath=<path to to>\vivisect
    szIns = szPrev = ''
    instr_list = []

    outputparamlst = process_instructions(d)
    all_instr_list = outputparamlst[0]
    final_offset_msg = outputparamlst[1]

    decoder_funcs = [decode_shikata_ga_nai, decode_call_to_self]
    try:
        for decoder_func in decoder_funcs:
            out_params = decoder_func(d, all_instr_list)
            if out_params is not None and out_params[0] is not None:
                szd = out_params[0]
                iLen = out_params[1]
                key = out_params[2]
                iXorOffset = out_params[3]
                szMsg = out_params[4]
                szOut += szMsg + '\n'

                outputparamlst = process_instructions(szd)
                all_instr_list = outputparamlst[0]
                final_offset_msg = outputparamlst[1]
                d = szd

    except Exception as e1:
        print(e1)

    for i in range(0, len(all_instr_list)):
        instr_lst = all_instr_list[i]
        szIns = instr_lst[2]
        szOut += '%s %s %s' % (instr_lst[0], instr_lst[1].ljust(16), szIns)
        if (i > 0):
            szPrev = all_instr_list[i-1][2]

        if (szIns == 'call ebp'):
            szDword = None
            if (szPrev.find("push 0x") >= 0 or re.search("mov e\wx,0x",szPrev) >= 0):
                szDword = szPrev[-10:]
            if (i > 2 and all_instr_list[i-1][1] == "0000" and all_instr_list[i-2][1] == "0000"):
                szDword = all_instr_list[i-3][2][-10:]
            if szDword is not None:
                if szDword in APIDict.keys():
                    szOut +=  " --> APICALL " + APIDict[szDword] + '\n';
                else:
                    szOut += '\n'
            else:
                szOut += '\n'
        elif (szIns.find('push 0x') >= 0 and szIns.find('0002')>0 and szPrev.find('push 0x') >= 0 ):
            #decode addr and port
            #0x000000ad 683418905b       push 0x5b901834 IP
            #0x000000b2 68020001bb       push 0xbb010002 port in highword
            szPort = szIns.split(' ')[1][2:6]
            szIP = szPrev.split(' ')[1]
            hexIP = int(szIP, 16)
            hexPort = int(szPort, 16)  
            hexPort = ((hexPort & 0x0000FF00) >> 8)  + ((hexPort & 0x000000FF) << 8) 
            szOut += "--> NETWORK IP %s.%s.%s.%s:%s\n" % (hexIP & 0x000000FF, (hexIP & 0x0000FF00) >> 8, (hexIP & 0x00FF0000)>>16, (hexIP & 0xFF000000) >> 24 , hexPort)
        elif (szIns.find('push 0x') >= 0 or (szIns.find('mov ') >= 0 and szIns.find(',0x') > 0)):
            szDword = szIns.split('0x')[1] # push 0x00707474  --> 007907474
            ## if dword is displayable characters (or NUL) then concatenate into a string
            szdw = ''.join([chr(int(''.join(c), 16)) for c in zip(szDword[0::2],szDword[1::2])])
            fContinue = True
            ## ignore DWORDs with non-ASCII bytes: push 0xe553a458--> 'SX'
            ## but allow ones with NULL bytes:     push 0x00003233--> '23'
            for c in szdw:
                if c in string.printable or ord(c) == 0:
                    pass  # keep going
                else:
                    fContinue = False
                    break
                
            if fContinue:
                szbytes = ''.join(map(lambda c: c if c in string.printable else '', szdw))
                szbytes = szbytes.replace('\r',' ').replace('\n','')
        
                if len(szbytes) >= 2:
                    szOut += "--> STR '" + szbytes + "'"
            szOut += '\n'
        else:
            szOut += '\n'
        szPrev = szIns
    
    return szOut


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description= \
    """Attempt to decode PowerShell scripts by looking for some common encoded data. It defaults to reading from stdin.
    \n
    REQUIREMENTS: This script uses vivisect for PE parsing and dissasembly: https://github.com/vivisect/vivisect. Set the PYTHONPATH as appropriate.
    """
    )
    parser.add_argument('--verbose','-v', help='Enable verbose mode', action='store_true', default=False)
    parser.add_argument('--resolve_apis','-r', help='Attempt to resolve API hashes', action='store_true', default=False)
    parser.add_argument('--dumpapis','-api', help='Dump APIs and hashes', action='store_true', default=False)
    parser.add_argument('--apidb','-db', help='Load APIs and hashes from a DB', action='store', type=str,default=None)
    parser.add_argument('--shellcode','-sh', help='Shellcode in the format of 0xeb,0x90,...', action='store', type=str,default=None)
    parser.add_argument('--file','-fi', help='Shellcode is contained in an input file', action='store', type=str,default=None)
    args = parser.parse_args()

    fVerbose = args.verbose
    szDbPath = args.apidb
    fResolveAPIs = args.resolve_apis
    if szDbPath is not None:
        fResolveAPIs = True

    if args.dumpapis:
        fVerbose = True
        prepareAPIs()
        sys.exit(0)

    sz = ''
    if args.file is not None:
        file = open(args.file, 'r')
        sz = ' '.join(file.readlines()).strip()
    else:
        sz = args.shellcode.strip()

    shellcode_bytes = None
    if '0x' in sz or '%0' in sz:
        if ',0x' in sz:
            shellcode_bytes = (''.join(sz.replace ('0x','').split(','))).decode('hex') 
        elif '%' in sz:
            shellcode_bytes = (''.join(sz.replace ('%','').split(','))).decode('hex') 
        elif ' 0x' in sz:
            shellcode_bytes = (''.join(sz.replace ('0x','').split(' '))).decode('hex') 
        
    disasm_str = dumpShellcode(shellcode_bytes)
    ## [all_instr_list, final_offset_msg] =  process_instructions(shellcode_bytes)
    ## for instr_item in all_instr_list:
    ##     print(instr_item)
    print(disasm_str)

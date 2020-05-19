'''
SPDX-License-Identifier: BSD Clause 2
Copyright 2017 Massachusetts Institute of Technology.
'''

import glob
import os

from keylime import common
from keylime import keylime_logging

config = common.get_config()
logger = keylime_logging.init_logging('tpm_ek_ca')
trusted_certs = {}
tpm_cert_store = config.get('tenant', 'tpm_cert_store')


def check_tpm_cert_store():
    if not os.path.isdir(tpm_cert_store):
        logger.error(f"The directory {tpm_cert_store} does not exist.")
        exit()
    else:
        for fname in os.listdir(tpm_cert_store):
            if fname.endswith('.pem'):
                break
        else:
            logger.error(f"The directory {tpm_cert_store} does not contain any .pem files.")
            exit()


def cert_loader():
    file_list = glob.glob(os.path.join(os.getcwd(), tpm_cert_store + "*.pem"))
    trusted_certs = []
    for file_path in file_list:
        with open(file_path) as f_input:
            trusted_certs.append(f_input.read())
    return trusted_certs




atmel_trusted_keys = {"ATM1": {"key": "E5AFB8C97B6E6D49C624FCFB6558D6B291A17B94EBF4186B590F5039F0E85659268BEB60D86A9CF6A03D477F5686288498AB90DFEE1722F3BE5C516B542BFEF18B849C1208BB8E85117D4B046ECB9D425B920015D29CC73163A084B84320670683FEA43BD7C7FBB29CC1FC0D6A1F992E47DB7E2B37726D3D465386F114AAF0BC8AF19734ED01F633B2FFF0F1674514393270205BBBEE93C87F33AD934F2FB20D5B9697F8E7877BEB2A054CA0EC8BFE233711D147215FABFE524E23F1D1025922782446889D64248E2D42951788BFAD2B6881D720319EA712433596C6536EBBAB00515DAD23EA8C54CDA8E9E4F57FF30CEFE6F89E6CAE06B74E20EE5DBD37A4EF",
                         "exponent": "10001"},
                "ATM2": {"key": "E9EFE830CCAFECD3E534AA3D03B96CC090E4135E0B6464AC2A2472CF225EDAA1C2A01C2C644AB7415DB0E1DB9C9E070ECAC45A7330DDF0292EF59DF7D9D6E2F53ABA4596A993F78BEE670117F5C136EED67EDDCF0D14F3B3C829337C451E8E7DF8E02379AC774C4F3247A3E18A2A69E36B88F5FD7CE2F42C830CC458DCFA90C50FE66C1EDC79BDCBC4654F3AE9240B55B56F70ECB9A849E3871E0CEC1061BDAB91763E463A5F416DF5E0D06883A54E87E4487CEF1B654BBFC30920D3239D7ACF9EF17C76A1B7F25CC022F0DF24A2B11393236366A815CD5D7C84900EFE2C631D366FA8F07C397CA450ABC02CC7EDC5A6204D210F6055D8BA6EAD44538BE92431",
                         "exponent": "10001"},
                "ATM3": {"key": "98501401327FF3121EB855B468A3597300AD0CB0CE4281887B3FAC83AE04989FAB10A3477CF423EDE7B7531880456A0BBE6ACCC0C6451D756E1DBE90E905011F63A65197E17015E6F7865B5EB150C83C68B11DE553E259BB924AD17EFA919010B62048DBF52424CB74C51526D4FEE92272A7AA4F47630D87A70AC2619208EFC47637C6DF1890173A9CF5A0EA48EE35477B0B4963F82E9F58E05EE3B0356FB5A2E0DA52B07FF2DF66D25BECA1EA9DBAAD0D86F97800BEA4C55169E2C497DE016E48E45C6C53F886EED4309CBA839F5D6EC829BA56E5B5DDBE1C3AB111AE153CE7B72250B8894B28D3DD6FABE578F53858399D135C58E4D5D35D71316E2B63BC91",
                         "exponent": "10001"},
                "ATM4": {"key": "C6D975B1A96EFF64977AA08632D69CD06302AB1E907A1E0AB6BBE23DF19574E6E4B2EC8644F3EE696DB9FE860D18B95FDB1FE40E592707679914C896F28B4A5D5FB13B9D2E15CC684C75D9D709CC0FCC7A0A0334CF48F70D0E5DD1EBB9B1144377B187604A6EBCC8F4C7CA6091993E0BE531DA15A58FCC448840C7F2AE70C8FE405FDD86929A1400BD1EE2F515EFF70210172C2CEB3C3AAEAB2B39A283CDA4B0388BFD39FFF13B6C4A6500C13FC5CCCFE08BBF71D03D611ED5F22CE14F0C8ACECB7777733E5030E4922C31C68E6A1A0C1174FAB701449082536881B5F20C05EBC93B52015268FF1207AB1D659A7F9A4D34900BEB678079E6962A6E4E697E9B55",
                         "exponent": "10001"},
                "ATM5": {"key": "AA0D458E1390FC6B2A8142FE59205C7D8AF7864C7197510168222A8A895CD51E5399969B687A025082668705DF146845BE166B23401C12A21800D2E0634AE2BE7E21EAF57EAEBC2DC4CD57ED7F21993F8076FC4BDA9F65382A7B5CDA50D91C3EA3FD8986E05252FFA8A56ECAEB03EE9B0529CB880BF9D028CD9C818DA9F90A8F6C3F9621DE4746DFE7B346C7F17F70A74BBE8D8631E094AF4059474CD5CEA6146A933FE7D4F72493A6869BAE70D4CC871E76EE4EB0C65AE4BD4B78B287AEAADB3376FDF79694F513EB210A0EDF1F8149ABBD01BD1DEB5E33A43D13796C23053ED8E6B220D786C8C7B0E203EE241911397C766DA5D496A6026696470E6D249DBD",
                         "exponent": "10001"},
                "ATM6": {"key": "C3DB3DCA4A60CC7D418ABCFC25598773F8D7352685B0341833D85C4B7E75DCFEDAAD2FABFE6BAC994A9F7726D8FC643CF98A8003A219ABEC65199ED65049B1BE8FC79679BF1508F77A96460F7AEE0299BEF1D2D5E07BECE118D9092F1C7E9911672821FA745DAD9DDA0306518D06E1BE5F26009390D91A7D00D699333623ADEEDA764BAA2050DAF379CA827E1790C21FB7E32D84EBDC318999B522FAE20BC0359ECF8ABC81D9C3214BED3200C18AFCEAA6D042C8464F30A8047F977B71455C68404A80F5F064D9BBC63625AF6BDD9C87108BA445FDF827195AF51E1FA529E5AD840F1C3C060C44D0BEACAA320D5A7DAE374C7B8E52B2B20F97132A3BA94A4C45",
                         "exponent": "10001"},
                "ATM7": {"key": "95845F0C3DDB30907BC3A165F8A7B3A08684933CFED9509E17CBF7A21B0D9D228281CC7CBA4ED27B2A79D1B12D2C1EAF3B3C2070CE568C522D2B260B65A1ED3F8DEADE21ECBC84A300635C606710DCDACCE226BAA5CDA0795ADABA995D3D375014E423C1DFB43FF436FD131B598EA0FAC6E3203B48B44735BE17FA6C8DD38A74FE6C6C715DD47D07AA9680B35CFC7DF5C2C04D3769CFBF52B8C04F0C59F015EE170AD8DA08735CC6118F888963ED5D2BB8F339AF4B6971296598BA21C1C02B799ECFD4ECCF174A391A8FB49B843D36C8AC2231ABEEED230071E49658C06E863826F7FCDF3003CA3BDC1E422C5509EB97B2907279FB1E90FBA4E6885B58E4BF6F",
                         "exponent": "10001"},
                "ATM8": {"key": "CA55DA838266CE8A9A4CAF1E09C4A30D238645CAD7F082BF7C16B080458A0203F2FF2BBEF051975CAD745C3788D5F9A501E7C3AFBDF8F429FEBFDFF2F8C7DF5C876E282A91E593FD335F9F064EE4E65E31D92782F4D7C8306F9CD3227A9B59049AC48DD389E52A4F1FA28E782FB0D8F8A9237E1E843F1CB3C6C303AAA4EB3227C14E117692AA392940437418C890E507D5D6CB5868C4814A4AA1C0AED8CE3553B8E68D3A1AB6403E77757E3F2411178FE52644D88AFE89CB5665D6AA4490BBD1D2A2ABCE81E43A28FBCC1A50FF8E81D815B5A4046353B008A7736D7D2E531CBE7D9A95F1A6ECA3EB2DA1D30C4D55190F6699D50346561E0CFD2784DC22000D3F",
                         "exponent": "10001"},
                "ATM9": {"key": "C5AD170489418FDB796D807CD4279A9A5577237AD36AD860C949F654BEFFC27836BCAE71EC10776B5C235EDE64FEEC11FCCE6D7C80CE4A3BA0FD27437D35A46517BCD888FFA1824ECAD72B173133A2E219540EEDFEE29D5F3470CFB759E8B3E7355929F06896503083A5334D9A7BE2799723AA87DA8C371CD040BBDB4353F8DAA690025DD2A60CB3E8B84C0DA89B60B62F1A64ABE61D269DA924E08242AB82C262D707C3B1ADD7635F8416E661F38A0C787DA9C2FC625C5EE4503D7A8BAEE1D9956994A94ED297AC99125B88B476C1AE2E01C43DD0EDE5C7D2C337AD919408BAF794C3D78C6B1FA688194F8CCBAF4EF9408C6DC1EE4E5299EC954EB5737E1707",
                         "exponent": "10001"},
                "ATM10": {"key": "D4711E0A7F36AFC56B83AE21A30BEDB3FD988F9CAE5E112FEC5C146884A8EEB6059C06ECB7231518DB0BDB8ADE456EDA8B28FAE621C4A23C7509AAF7265BBC8587D3AA26A016610AFEA7BC7AB11AB708398C543419D2B76BD4F0EE78586638E97BDF2C4632FF0D0948E4D88A0A53C5E1936A238D7C3069B398F37F40DC519CA240AF92D313C15908C4A19B957D7A07BBDA82E3E157CFBB3DBD7D02C1656240DBE354CBA802A5C51285E8C67E6F434C6064D26DF0AEEAB25EECCACC9E14D17A399D3AA9ED957F24B6D25A74C9C6CEF6859E03D676E2D2968F42070AE4561B2304355AE12937940C7E296C01915BA2442741AFA35F647395EA1AD265115449C64D",
                          "exponent": "10001"},
                "ATM11": {"key": "AAB4B5122D55BCBC5561636FFECDF96989876B930E9EF4326E05BF8B55EE20D66E3D0A98370D36C2B59103979FB76B6CF859090EF6F3E9E76DA87DF40A3C7EA6613D3AFA2D63B3BBADBA2BBB3D96D8FA5C434FE29CB522C4D8AAFC0F2088A45625A4CDB2217A54B3445847B9B1FDEB7BAF82FD94147F0BA9339E9B53426B20CC44829F1208582E42C37072ADADC6DAF5BA3817E0F37A0CE7ADE8172B4E9B18BF12A140F6CBFD37E5FE432A615CEAAB2AC11A0920F3ED854713BA6D54890B0AF2AC0DFB670920265DE4FEA89B4C5CF02557C99C6693E7B2FF4D4549470003B5537EA0915C41A991ECDE9522EA21C7B7E9ED4F2DF27ACA859A48C0AE34E612C4D7",
                          "exponent": "10001"},
                "ATM12": {"key": "D51E1F5416D423BB6C691B92D15BC74E2A2E67B2FF1C0A241C8B28CDE2CA6A68ACB67A0234A332CF8D29C067A72BC9745E7BC9BDEA00953FB7B5B2A699EA3B891D503F6F2C84DF2082739B1D9A4137670F8B24A1D00F2E608117637B0932B359FE1D8C31B8D80F69D4CAB795A6E8FE9B2B526EF981D5EA9C8FDA782416356AAC1706B9B40EAC595C9B1534192327B73D905CB7CDEF3271C4C52B1FF05DEEEF3C782858A03B44BB4CDA2FE9A49750813FC8B9B3AB8594F258FA6F2D00E935FD29FD20E6072C37FD1CE29CF165C54980781CEF4C3C0CEE312C64851018364806189F2B8E552CBAD08834D338BF1E570F43F07D339FC009BBB705F70F686108FA7D",
                          "exponent": "10001"},
                "ATM13": {"key": "C12BD4CD44118C3DCAC99309BB9099B0754BA803749814FCEA78AF8C257E4611EC474B92535D7434A8DBD881D73377D8689960BD945301027773C8CF7346D5B42D3EE76D5028AB7CE8E2E2D3E9EB353D90CCBB6B260C7A791A188AEF6C7B6174BBFCC1F8F1D0D11F2A54E235C70D161552B6C36FA6453DD637851DA74467E8B28F4570AAE7D24F7EE0FB84D0559B0A7DBB38F64CBA7C96331149B0A14637A4BBD1F81BE6F6A9AE307F683D479FC4AAAE5C33062C0F8DF9EDCBA195FA964310FAD49F77AE8D877F9FB7D09AD9176CA8FD35F9A1C750AA7BCB79AA5ED4A6464C3AE290D5C3F5E221479DF24F868100AFD107CB1CB1BC239F9B67A0804ED06004C3",
                          "exponent": "10001"}
}

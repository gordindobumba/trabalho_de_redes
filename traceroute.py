import util

# Seu programa deve enviar TTLs no intervalo [1, TRACEROUTE_MAX_TTL], inclusive.
# Tecnicamente, o IPv4 permite TTLs de ate 255, mas, na pratica, isso e excessivo.
# A maioria das implementacoes de traceroute limita o valor a aproximadamente 30.
# Os testes fornecidos assumem que este valor nao sera alterado.
TRACEROUTE_MAX_TTL = 30

# A Cisco popularizou o uso das portas UDP no intervalo [33434, 33464] para traceroute.
# Embora isso nao seja um padrao formal, alguns roteadores na Internet respondem de forma
# mais consistente com mensagens ICMP de tempo excedido para pacotes UDP enviados a essas
# portas. Voce pode usar outra porta, mas este valor e adequado para o projeto.
TRACEROUTE_PORT_NUMBER = 33434

# Pacotes podem ser descartados na Internet. PROBE_ATTEMPT_COUNT e o numero maximo de
# sondas que a funcao traceroute deve enviar para um mesmo TTL antes de seguir adiante.
PROBE_ATTEMPT_COUNT = 3

def buffer_to_bits(buffer: bytes):
    return ''.join(format(byte, '08b') for byte in [*buffer])

def bits_to_int(b: str, l: int, r: int):
    return int(b[l:r], 2)

def bits_to_ip(b: str, l: int, r: int):
    partes = [str(int(b[i: i + 8], 2)) for i in range(l, r, 8)]
    return '.'.join(partes)

class IPv4:
    # Cada membro abaixo corresponde a um campo do cabecalho IPv4. Os campos aparecem
    # na mesma ordem em que estao no pacote. Todos devem ser armazenados na ordem de
    # bytes do host.
    #
    # Modifique apenas o metodo __init__() desta classe.
    version: int
    header_len: int  # Comprimento em bytes, e nao o valor bruto armazenado no pacote.
    tos: int         # Tambem chamado de bits DSCP e ECN.
    length: int      # Comprimento total do pacote.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        b = buffer_to_bits(buffer)
        self.version =      bits_to_int(b, 0, 4)
        self.header_len =   bits_to_int(b, 4, 8) * 4
        self.tos =          bits_to_int(b, 8, 16)
        self.length =       bits_to_int(b, 16, 32)
        self.id =           bits_to_int(b, 32, 48)
        self.flags =        bits_to_int(b, 48, 51)
        self.frag_offset =  bits_to_int(b, 51, 64)
        self.ttl =          bits_to_int(b, 64, 72)
        self.proto =        bits_to_int(b, 72, 80)
        self.cksum =        bits_to_int(b, 80, 96)
        self.src =          bits_to_ip(b, 96, 128)
        self.dst =          bits_to_ip(b, 128, 160)

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"offset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Cada membro abaixo corresponde a um campo do cabecalho ICMP. Os campos aparecem
    # na mesma ordem em que estao no pacote. Todos devem ser armazenados na ordem de
    # bytes do host.
    #
    # Modifique apenas o metodo __init__() desta classe.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = buffer_to_bits(buffer)
        self.type = bits_to_int(b, 0, 8)
        self.code = bits_to_int(b, 8, 16)
        self.cksum = bits_to_int(b, 16, 32)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Cada membro abaixo corresponde a um campo do cabecalho UDP. Os campos aparecem
    # na mesma ordem em que estao no pacote. Todos devem ser armazenados na ordem de
    # bytes do host.
    #
    # Modifique apenas o metodo __init__() desta classe.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = buffer_to_bits(buffer)
        self.src_port = bits_to_int(b, 0, 16)
        self.dst_port = bits_to_int(b, 16, 32)
        self.len = bits_to_int(b, 32, 48)
        self.cksum = bits_to_int(b, 48, 64)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"


# TODO: sinta-se a vontade para adicionar funcoes auxiliares, se desejar.

def calcular_inicio_cabecalho_transporte(buffer: bytes) -> int:
    return (buffer[0] & 0x0F) * 4
 
 
def classificar_resposta_icmp(icmp: ICMP) -> str:
    if icmp.type == 11 and icmp.code == 0:
        return "tempo_excedido"
    if icmp.type == 3 and icmp.code == 3:
        return "porta_inalcancavel"
    return "ignorar"
 
 
def deve_encerrar_traceroute(ip_origem: str, ip_destino: str, icmp: ICMP) -> bool:
    return (ip_origem == ip_destino and classificar_resposta_icmp(icmp) == "porta_inalcancavel")
 
 
def registrar_roteador_descoberto(roteadores_ttl: list[str], endereco: str):
    if endereco not in roteadores_ttl:
        roteadores_ttl.append(endereco)

def interpretar_resposta_da_sonda(buffer: bytes):
    TAMANHO_CABECALHO_ICMP = 8
    TAMANHO_CABECALHO_UDP = 8
    TAMANHO_MINIMO_IPV4 = 20
 
    if len(buffer) < TAMANHO_MINIMO_IPV4:
        return None
 
    inicio_icmp = calcular_inicio_cabecalho_transporte(buffer)
    if inicio_icmp < TAMANHO_MINIMO_IPV4:
        return None
    ip_externo = IPv4(buffer[:TAMANHO_MINIMO_IPV4])
    if ip_externo.proto != util.IPPROTO_ICMP:
        return None
 
    resto = buffer[inicio_icmp:]
    if len(resto) < TAMANHO_CABECALHO_ICMP + TAMANHO_MINIMO_IPV4:
        return None
    icmp = ICMP(resto[:TAMANHO_CABECALHO_ICMP])
 
    pacote_original = resto[TAMANHO_CABECALHO_ICMP:]
    inicio_udp = calcular_inicio_cabecalho_transporte(pacote_original)
    if inicio_udp < TAMANHO_MINIMO_IPV4 \
            or len(pacote_original) < inicio_udp + TAMANHO_CABECALHO_UDP:
        return None
    ip_original = IPv4(pacote_original[:TAMANHO_MINIMO_IPV4])
    if ip_original.proto != util.IPPROTO_UDP:
        return None
    udp_original = UDP(pacote_original[inicio_udp:inicio_udp + TAMANHO_CABECALHO_UDP])
 
    return ip_externo, icmp, ip_original, udp_original
 

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """Executa o traceroute e retorna o caminho descoberto.

    A funcao deve chamar util.print_result() com o resultado das sondas de cada TTL
    para mostrar o progresso da execucao.

    Argumentos:
    sendsock -- socket UDP usado para enviar as sondas do traceroute.
    recvsock -- socket no qual serao recebidas as respostas ICMP.
    ip -- endereco IP do host de destino.

    Retorno:
    Uma lista de listas representando os roteadores descobertos para cada TTL sondado.
    A lista de indice i contem todos os roteadores encontrados com uma sonda de TTL i+1.
    Os roteadores podem aparecer em qualquer ordem. Se nenhum roteador for encontrado,
    a lista correspondente pode ficar vazia. Se ip for descoberto, ele deve aparecer
    como o ultimo elemento da lista externa.
    """
    
    caminho = []
    # TODO: adicione sua implementacao.
    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        roteadores_ttl = []
        destino_alcancado = False
        sendsock.set_ttl(ttl)
 
        for _ in range(PROBE_ATTEMPT_COUNT):
            sendsock.sendto("Potato".encode(), (ip, TRACEROUTE_PORT_NUMBER))
 
            while recvsock.recv_select():
                buffer, _ = recvsock.recvfrom()
                resposta = interpretar_resposta_da_sonda(buffer)
                if resposta is None:
                    continue
 
                ip_externo, icmp, ip_original, udp_original = resposta
                if ip_original.dst != ip \
                        or udp_original.dst_port != TRACEROUTE_PORT_NUMBER:
                    continue
                if classificar_resposta_icmp(icmp) == "ignorar":
                    continue
 
                if deve_encerrar_traceroute(ip_externo.src, ip, icmp):
                    destino_alcancado = True
                else:
                    registrar_roteador_descoberto(roteadores_ttl, ip_externo.src)
                break
 
            if destino_alcancado: break
 
        if destino_alcancado:
            roteadores_ttl = []
            registrar_roteador_descoberto(roteadores_ttl, ip)
 
        util.print_result(roteadores_ttl, ttl)
        caminho.append(roteadores_ttl)
 
        if destino_alcancado: break
    return caminho


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)

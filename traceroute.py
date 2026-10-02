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
        pass  # TODO: implemente a interpretacao do cabecalho IPv4.

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
        pass  # TODO: implemente a interpretacao do cabecalho ICMP.

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
        pass  # TODO: implemente a interpretacao do cabecalho UDP.

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"


# TODO: sinta-se a vontade para adicionar funcoes auxiliares, se desejar.


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
    a lista correspondente pode ficar vazia. Se `ip` for descoberto, ele deve aparecer
    como o ultimo elemento da lista externa.
    """
    sendsock.set_ttl(1)
    sendsock.sendto("Potato".encode(), (ip, TRACEROUTE_PORT_NUMBER))
    if recvsock.recv_select():
        buffer, address = recvsock.recvfrom()
        print(buffer.hex())

    # TODO: adicione sua implementacao.
    # for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
    #     util.print_result([], ttl)
    # return []


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)

from typing import List
import hashlib
import hmac


def give_md5(messages: List) -> str:
    # fonction de hachage
    m = hashlib.md5()
    for message in messages:
        bytes_message = format_str_to_b(message)
        m.update(bytes_message)
    return m.hexdigest(), m.digest_size, m.name

def give_sha224(messages):
    # fonction de hachage
    s = hashlib.sha224()
    for message in messages:
        bytes_message = format_str_to_b(message)
        s.update(bytes_message)
    return s.hexdigest(), s.digest_size, s.name


def give_hmac(messages: List, secret_key: str) -> str:
    # clé secrète
    bytes_secret_key = format_str_to_b(secret_key)
    # fonction de hachage
    h = hmac.new(bytes_secret_key, digestmod=hashlib.sha1)
    for message in messages:
        bytes_message = format_str_to_b(message)
        h.update(bytes_message)
    return h.hexdigest(), h.digest_size, h.name


def format_str_to_b(string_to_b: str):
    binary_converted = string_to_b.encode('UTF-8')
    return binary_converted


def powm(b: int, e: int, m: int) -> int:
    """
         Retourne b^e(mod m)

    Nous verrons qu’en cryptographie asymétrique, en particulier avec
    l’algorithme RSA, on a souvent besoin de calculer b^e (mod m)
    explicitement où b, e, m sont de “grands” entiers naturels. Ce calcul
    s’appelle exponentiation modulaire. b est appelé la base, e l’exposant
    et m le module.
    Par exemple, considérons le calcul de 341^943 (mod 1403). La méthode
    naïve consisterait à élever 341 à la puissance 943 puis effectuer la division
    euclidienne du résultat par 1403, le reste de cette division étant le nombre
    cherché.
    Une première difficulté est d’avoir à effectuer 942 multiplications (en
    pratique, les nombres sont beaucoup plus grands) suivies d’une division
    euclidienne.
    Mais la difficulté principale (rédhibitoire en pratique) est, qu’avec cette
    méthode, on est conduit à manipuler des nombres de plus en plus grands.

    Fort heureusement, il existe un algorithme efficace, appelé exponentiation
    par carrés (ou exponentiation rapide) qui combine deux opérations
    élémentaires : l’élévation au carré et la multiplication par la base b.

    :param b:
    :param e:
    :param m:
    :return:
    """

    result = 1
    while e > 0:
        if e & 1 > 0:  # e est impair
            result = (result * b) % m  # on multiplie par la base b
            yield result

        e >>= 1  # on divise e par 2 (en décalage de bit vers la droite)
        b = (b * b) % m  # on élève la base b au carré
    return result


if __name__ == '__main__':
    messages_to_hash = ['Hello', 'you !', 'I love you.']
    print(f"Md5 : {give_md5(messages_to_hash)}")
    print(f"Sha224 : {give_sha224(messages_to_hash)}")
    secret_key = 'loulou'
    print(f"HMAC : {give_hmac(messages_to_hash, secret_key)}")
    print(list(powm(10, 2, 2)))



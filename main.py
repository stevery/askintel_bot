import re
import os
import sys
import platform as pf
import logging
import pprint
import math
from telegram.ext import Updater
from telegram.ext import CommandHandler
from telegram.ext import MessageHandler, Filters

import easyntelligence

mypf = pf.platform()
dir_path = os.path.dirname(os.path.abspath(__file__))
seperator = ""
if re.search(r'^windows', mypf, re.I):
    seperator = "\\"
elif re.search(r'^(linux|Darwin)', mypf, re.I):
    seperator = "/"
else:
    print("Not supported platform")
    print("your os is: {}".format(mypf))
    sys.exit(0)

lib_path = seperator.join(dir_path.split(seperator)[:-3])
sys.path.append(lib_path)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

ei = easyntelligence.EasyIntell()
MAXLEN = 4096


def start(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="I'm a bot for asking security intelligence, please ask to me!")


def help(bot, update):
    bot.send_message(chat_id=update.message.chat_id,
                     text='''/start, start command describes this bot
/ask (ip|domain|hash), ask command fetches cti from vt, xfe, shodan, and etc
/help, help''')

def echo(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text=update.message.text)

# todos
# hash
# md5: [a-fA-F\d]30
# sha-1: [a-fA-F\d]40
# sha-256: [a-fA-F\d]64
# domain, url
# todos
# too many if statements, need to be functionize


def message_cleaner(bot, update, args):
    try:
        if args is not None:
            messages = pprint.pformat(args, indent=4)
            # The maximum message length of telegram is 4096 bytes
            if len(messages) < MAXLEN:
                bot.send_message(chat_id=update.message.chat_id, text=messages)
            else:
                bot.send_message(chat_id=update.message.chat_id, text=messages)
                bot.send_message(chat_id=update.message.chat_id, text="The message is too long (over {} bytes), it is snipped ".format(MAXLEN))
                #for i in range(math.ceil(len(messages)%MAXLEN)):
                #    bot.send_message(chat_id=update.message.chat_id, text=messages[i*MAXLEN:i*MAXLEN+MAXLEN])
        else:
            bot.send_message(chat_id=update.message.chat_id, text='None')
    except Exception as e:
        bot.send_message(chat_id=update.message.chat_id, text="[Error] {}".format(e))
        pass

def asks(bot, update, args):
    args = args[0].strip()
    result = ""
    ip_search = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    md5_search = re.compile(r'^[a-fA-F\d]{32}$')
    sha1_search = re.compile(r'^[a-fA-F\d]{40}$')
    sha256_search = re.compile(r'^[a-fA-F\d]{64}$')
    domain_search = re.compile(r'((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*')
    if ip_search.search(args):
        ei.ask_ip(args, itype='ip')
        bot.send_message(chat_id=update.message.chat_id, text="You asked for ip address: {}".format(args))
        bot.send_message(chat_id=update.message.chat_id, text="https://www.virustotal.com/#/ip-address/{}".format(args))
        message_cleaner(bot, update, ei.result['virustotal'])

        bot.send_message(chat_id=update.message.chat_id, text='https://www.shodan.io/search?query={}'.format(args))
        message_cleaner(bot, update, ei.result['shodan'])

        bot.send_message(chat_id=update.message.chat_id, text='https://exchange.xforce.ibmcloud.com/ip/{}'.format(args))
        message_cleaner(bot, update, ei.result['xfe'])
        

    elif md5_search.search(args) or sha1_search.search(args) or sha256_search.search(args):
        ei.ask_hash(args, itype='hash')
        bot.send_message(chat_id=update.message.chat_id, text='You asked hash value for: {}'.format(args))
        #bot.send_message(chat_id=update.message.chat_id, text="https://www.virustotal.com/#/file/{}".format(args))
        message_cleaner(bot, update, ei.result['virustotal'])
        message_cleaner(bot, update, ei.result['xfe'])

    elif domain_search.search(args):
        ei.ask_domain(args, itype='domain')
        bot.send_message(chat_id=update.message.chat_id, text='You asked domain value for: {}'.format(args))
        message_cleaner(bot, update, ei.result['virustotal'])
        
    else:
        result = "You asked wrong queries. {}".format(args)
        bot.send_message(chat_id=update.message.chat_id, text=result)


def main():
    updater = Updater(token=ei.teletoken.strip())
    dispatcher = updater.dispatcher

    # command for start
    start_handler = CommandHandler('start', start)
    dispatcher.add_handler(start_handler)

    # command for help
    help_handler = CommandHandler('help', help)
    dispatcher.add_handler(help_handler)

    # command for shell
    echo_handler = MessageHandler(Filters.text, echo)
    dispatcher.add_handler(echo_handler)

    # command for ask
    ask_handler = CommandHandler('ask', asks, pass_args=True)
    dispatcher.add_handler(ask_handler)

    # start bot
    updater.start_polling()


if __name__ == "__main__":
    main()
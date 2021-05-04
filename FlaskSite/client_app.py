#!/usr/bin/python3

import webbrowser

from datetime import datetime
from tkinter import *
from tkinter import ttk
from tkinter import messagebox

from client import *


class ClientApp:
    def __init__(self, window):
        self.client = ChainClient()

        self.window = window
        self.window.title("NewsLedger")
        self.window.geometry('640x480')

        self.tab_control = ttk.Notebook(window)
        self.chain_tab = Frame(self.tab_control)
        self.profile_tab = Frame(self.tab_control)
        self.article_tab = Frame(self.tab_control)
        self.invite_tab = Frame(self.tab_control)
        self.nodes_tab = Frame(self.tab_control)

        self.tab_control.add(self.chain_tab, text='Chain')
        self.tab_control.add(self.profile_tab, text='Profile')
        self.tab_control.add(self.article_tab, text='Article')
        self.tab_control.add(self.invite_tab, text='Invite')
        self.tab_control.add(self.nodes_tab, text='Nodes')

    def chain_init(self):
        for child in self.chain_tab.winfo_children():
            child.destroy()

        chain_header = Frame(self.chain_tab, highlightbackground='gray', highlightthickness=1)
        chain_label = Label(chain_header, text="Local instance of blockchain", anchor='w')
        chain_label.pack(side=LEFT, fill=BOTH, expand=True)
        update_btn = Button(chain_header, text="Update", command=lambda: self.window.after(0, self.update_state))
        update_btn.pack(side=RIGHT, fill=Y, expand=False)
        chain_header.pack(fill=BOTH, expand=False)

        chain_frame = LabelFrame(self.chain_tab, text="Transaction history", highlightbackground='gray', highlightthickness=1)

        scroll = Scrollbar(chain_frame, orient=VERTICAL)
        chain_canvas = Canvas(chain_frame)
        scroll.pack(fill=Y, side=RIGHT, expand=False)
        scroll.config(command=chain_canvas.yview)

        inner_frame = Frame(chain_canvas)

        for block in self.client.chain[::-1]:
            for t in block['transactions'][::-1]:
                transaction = Frame(inner_frame, width=615, height=80, highlightbackground='gray', highlightthickness=1)

                operation = Label(transaction, text=t['operation'], width=16, anchor='nw')
                operation.pack(side=LEFT, fill=BOTH, expand=False)

                tstamp = Label(transaction, text=datetime.fromtimestamp(t['timestamp']).strftime('%d.%m.%Y %H:%M'), anchor='ne')
                tstamp.pack(side=RIGHT, fill=BOTH, expand=False)

                recipient = Label(transaction, text=f"{t['sender'][:6]}...   -->   {t['recipient']}", width=32, anchor='w')
                recipient.pack(side=LEFT, fill=X, expand=False)

                info_btn = Button(transaction, text="Info", command=self.func_handler(self.transaction_info, t))
                info_btn.pack(side=RIGHT, fill=X, expand=False)

                transaction.pack_propagate(0)
                transaction.pack(fill=BOTH, expand=True)

        inner_frame.pack(fill=BOTH, expand=True)
        inner_frame.bind("<Configure>", lambda e: chain_canvas.configure(scrollregion=chain_canvas.bbox('all')))

        chain_canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        chain_canvas.pack(fill=BOTH, expand=True)
        chain_canvas.config(scrollregion=chain_canvas.bbox('all'), yscrollcommand=scroll.set)

        chain_frame.pack(fill=BOTH, expand=True)

    def profile_init(self):
        for child in self.profile_tab.winfo_children():
            child.destroy()

        profile_header = Frame(self.profile_tab, highlightbackground='gray', highlightthickness=1)
        my_key = b64encode(int.to_bytes(self.client.pubkey.n, KEY_LEN//8, 'big')).decode('utf-8')
        profile_label = Label(profile_header, text=f"{my_key[:6]}...{my_key[-4:]}", anchor='w')
        profile_label.pack(side=LEFT, expand=False, padx=40)
        profile_label.bind("<Button-1>", lambda e: messagebox.showinfo("Key info", f"{my_key}"))
        mkbtn = Button(profile_header, text="Manage keys...", command=self.func_handler(self.managekeys))
        mkbtn.pack(side=RIGHT, fill=Y, expand=False)
        profile_header.pack(fill=BOTH, expand=False)

        profile_body = Frame(self.profile_tab, highlightbackground='gray', highlightthickness=1)

        scroll = Scrollbar(profile_body, orient=VERTICAL)
        profile_canvas = Canvas(profile_body)
        scroll.pack(fill=Y, side=RIGHT, expand=False)
        scroll.config(command=profile_canvas.yview)
        inner_frame = Frame(profile_canvas)

        account_info = LabelFrame(inner_frame, text="Account Info", width=620, height=90, highlightbackground='gray', highlightthickness=1)
        key_label = Label(account_info, text=f"Public key:  {my_key[:6]}...{my_key[-4:]}", anchor='w')
        key_label.pack(fill=X, expand=False, padx=50)
        key_label.bind("<Button-1>", lambda e: messagebox.showinfo("Key info", f"{my_key}"))
        status_label = Label(account_info, text=f"Status:  {'ACTIVE' if my_key in self.client.users else 'INACTIVE (%d / %d invites)' % (self.client.invites.get(my_key), VOTES_FOR_NEWBIE)}", anchor='w')
        status_label.pack(fill=X, expand=False, padx=50)
        balance_label = Label(account_info, text=f"Balance:  {self.client.balances.get(my_key)}", anchor='w')
        balance_label.pack(fill=X, expand=False, padx=50)
        account_info.pack_propagate(0)
        account_info.pack(fill=BOTH, expand=True)

        my_arts = LabelFrame(inner_frame, text="My articles")
        for art_name, article in self.client.articles.items():
            if article['author'] == my_key:
                article_frame = Frame(my_arts, width=615, height=80, highlightbackground='gray', highlightthickness=1)

                name = Label(article_frame, text=f"   {art_name}\n\n {article['link']}", width=24, anchor='nw')
                name.pack(side=LEFT, fill=BOTH, expand=False)
                name.bind("<Button-1>", self.func_handler(webbrowser.open, article['link']))

                tstamp = Label(article_frame, text=datetime.fromtimestamp(article['timestamp']).strftime('%d.%m.%Y %H:%M'), anchor='ne')
                tstamp.pack(side=RIGHT, fill=BOTH, expand=False)

                deposit = Label(article_frame, text=f"Deposit:  {article['deposit']}")
                deposit.pack(expand=True, ipadx=80)

                pos, neg = article['votes']['pos'], article['votes']['neg']
                time_passed = time() - article['timestamp']
                if time_passed <= VOTING_TIME:
                    status = f"VOTING till {datetime.fromtimestamp(article['timestamp']+VOTING_TIME).strftime('%d.%m.%Y %H:%M')}"
                elif time_passed <= VOTING_TIME + CONFIRM_TIME:
                    status = f"CONFIRMING till {datetime.fromtimestamp(article['timestamp']+VOTING_TIME+CONFIRM_TIME).strftime('%d.%m.%Y %H:%M')}"
                else:
                    if pos > (neg + pos) * POS_THRESHOLD:
                        status = "RATED TRUSTWORTHY"
                    elif neg > (neg + pos) * NEG_THRESHOLD:
                        status = "RATED FAKE"
                    else:
                        status = "MIXED RATING"

                votes = Label(article_frame, text=f"{status}\n[+ {pos}]  [- {neg}]  ({round(pos/(pos+neg)*100)} / {round(neg/(pos+neg)*100)} %)")
                votes.pack(expand=True, ipadx=80)

                article_frame.pack_propagate(0)
                article_frame.pack(fill=BOTH, expand=True)

        my_arts.pack(fill=BOTH, expand=True)
        inner_frame.pack(fill=BOTH, expand=True)
        inner_frame.bind("<Configure>", lambda e: profile_canvas.configure(scrollregion=profile_canvas.bbox('all')))

        profile_canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        profile_canvas.pack(fill=BOTH, expand=True)
        profile_canvas.config(scrollregion=profile_canvas.bbox('all'), yscrollcommand=scroll.set)
        profile_body.pack(fill=BOTH, expand=True)

    def article_init(self):
        pass

    def invite_init(self):
        pass

    def nodes_init(self):
        for child in self.nodes_tab.winfo_children():
            child.destroy()

        nodes_header = Frame(self.nodes_tab, highlightbackground='gray', highlightthickness=1)
        nodes_label = Label(nodes_header, text="Nodes list", anchor='w')
        nodes_label.pack(side=LEFT, fill=BOTH, expand=True)

        new_btn = Button(nodes_header, text="Import", command=self.func_handler(self.new_node))
        new_btn.pack(side=RIGHT, fill=Y, expand=False)
        nodes_header.pack(fill=BOTH, expand=False)

        nodes_frame = Frame(self.nodes_tab, highlightbackground='gray', highlightthickness=1)

        scroll = Scrollbar(nodes_frame, orient=VERTICAL)
        nodes_canvas = Canvas(nodes_frame)
        scroll.pack(fill=Y, side=RIGHT, expand=False)
        scroll.config(command=nodes_canvas.yview)

        inner_frame = Frame(nodes_canvas)

        for node in self.client.nodes:
            node_elem = Frame(inner_frame, width=620, height=20, highlightbackground='gray', highlightthickness=1)

            addr = Label(node_elem, text=node, anchor='w')
            addr.pack(side=LEFT, fill=BOTH, expand=False)

            del_btn = Button(node_elem, text="X", command=self.func_handler(self.del_node, node))
            del_btn.pack(side=RIGHT, fill=Y, expand=False)

            node_elem.pack_propagate(0)
            node_elem.pack(fill=BOTH, expand=False)

        inner_frame.pack(fill=BOTH, expand=True)
        inner_frame.bind("<Configure>", lambda e: nodes_canvas.configure(scrollregion=nodes_canvas.bbox('all')))

        nodes_canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        nodes_canvas.pack(fill=BOTH, expand=True)
        nodes_canvas.config(scrollregion=nodes_canvas.bbox('all'), yscrollcommand=scroll.set)

        nodes_frame.pack(fill=BOTH, expand=True)

    @staticmethod
    def func_handler(func, *args):
        return lambda e=None: func(*args)

    @staticmethod
    def transaction_info(t):
        messagebox.showinfo(f"Transaction info", repr(t))

    def update_state(self):
        res = self.client.resolve_conflicts()
        if res:
            self.chain_init()
            messagebox.showinfo("Chain update", "Chain successfully updated!")
        else:
            messagebox.showwarning("Chain update", "Could not update chain.")

    def managekeys(self):
        pass

    def new_node(self):
        popup = Tk()
        popup.title("New nodes")
        popup.geometry('300x400')
        label = Label(popup, text="Input node hosts here:")
        label.pack()
        inputtxt = Text(popup, height=20, width=40)
        inputtxt.insert(END, "http://0.0.0.0:1234\nhttp://1.1.1.1:567\n...")
        inputtxt.pack()

        def add_entered_nodes():
            nodes = inputtxt.get(1.0, 'end-1c').split('\n')
            nodes = set(nodes)
            actual_len = len(nodes)
            for node in nodes:
                if urlparse(node).netloc:
                    self.client.register_node(node)
                else:
                    actual_len -= 1
            self.client.save_nodes(self.client.node_file)
            self.nodes_init()
            popup.destroy()
            messagebox.showinfo("New nodes", f"{actual_len} nodes have been added" + (f"\n({len(nodes)-actual_len} invalid)." if len(nodes)-actual_len else "."))

        enter_btn = Button(popup, text=" Add ", command=add_entered_nodes)
        enter_btn.pack(side=RIGHT, expand=False)

        cancel_btn = Button(popup, text="Cancel", command=lambda: popup.destroy())
        cancel_btn.pack(side=LEFT, expand=False)

        popup.mainloop()

    def del_node(self, node):
        ans = messagebox.askyesno("Remove node", f"Remove node '{node}'?")
        if ans:
            self.client.nodes.remove(node)
            self.client.save_nodes(self.client.node_file)
            self.nodes_init()
            messagebox.showinfo("Remove node", "Node has been removed.")

    def run(self):
        self.chain_init()
        self.profile_init()
        self.article_init()
        self.invite_init()
        self.nodes_init()

        self.tab_control.pack(fill=BOTH, expand=True)
        self.window.mainloop()


def main():
    root = Tk()
    c = ClientApp(root)
    c.run()


if __name__ == "__main__":
    main()

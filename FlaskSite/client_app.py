#!/usr/bin/python3

# Client-side app for the project

import webbrowser

from datetime import datetime
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

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
        chain_label = Label(chain_header, text="Local instance of blockchain" + (" [INVALID CHAIN]" if not self.client.valid_chain(self.client.chain) else ""), anchor='w')
        chain_label.pack(side=LEFT, fill=BOTH, expand=True, padx=20)
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
        profile_label = Label(profile_header, text=f"Profile:  {my_key[:6]}...{my_key[-4:]}", anchor='w')
        profile_label.pack(side=LEFT, expand=False, padx=20)
        profile_label.bind("<Button-1>", lambda e: messagebox.showinfo("Key info", f"{my_key}"))
        mkbtn = Button(profile_header, text="Manage keys...", command=self.func_handler(self.managekeys))
        mkbtn.pack(side=RIGHT, fill=Y, expand=False)
        profile_header.pack(fill=BOTH, expand=False)

        profile_body = Frame(self.profile_tab, highlightbackground='gray', highlightthickness=1)

        scroll = Scrollbar(profile_body, orient=VERTICAL)
        canvas = Canvas(profile_body)
        scroll.pack(fill=Y, side=RIGHT, expand=False)
        scroll.config(command=canvas.yview)
        inner_frame = Frame(canvas)

        account_info = LabelFrame(inner_frame, text="Account Info", width=620, height=90, highlightbackground='gray', highlightthickness=1)
        key_label = Label(account_info, text=f"Public key:  {my_key[:6]}...{my_key[-4:]}", anchor='w')
        key_label.pack(fill=X, expand=False, padx=50)
        key_label.bind("<Button-1>", lambda e: messagebox.showinfo("Key info", f"{my_key}"))
        invites = self.client.invites.get(my_key)
        if not invites: invites = 0
        status_label = Label(account_info, text=f"Status:  {'ACTIVE' if my_key in self.client.users else 'INACTIVE (%d / %d invites)' % (invites, VOTES_FOR_NEWBIE)}", anchor='w')
        status_label.pack(fill=X, expand=False, padx=50)
        balance_label = Label(account_info, text=f"Balance:  {self.client.balances.get(my_key)}", anchor='w')
        balance_label.pack(fill=X, expand=False, padx=50)
        account_info.pack_propagate(0)
        account_info.pack(fill=BOTH, expand=True)

        my_arts = LabelFrame(inner_frame, text="My articles")
        for art_name, article in self.client.articles.items():
            if article['author'] == my_key:
                self.show_article(my_arts, art_name, article)

        my_arts.pack(fill=BOTH, expand=True)
        inner_frame.pack(fill=BOTH, expand=True)
        inner_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox('all')))

        canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        canvas.pack(fill=BOTH, expand=True)
        canvas.config(scrollregion=canvas.bbox('all'), yscrollcommand=scroll.set)
        profile_body.pack(fill=BOTH, expand=True)

    def article_init(self):
        for child in self.article_tab.winfo_children():
            child.destroy()

        art_header = Frame(self.article_tab, highlightbackground='gray', highlightthickness=1)
        art_label = Label(art_header, text="Articles list", anchor='w')
        art_label.pack(side=LEFT, fill=BOTH, expand=True, padx=20)

        new_btn = Button(art_header, text="New article...", command=self.func_handler(self.new_art))
        new_btn.pack(side=RIGHT, fill=Y, expand=False)
        art_header.pack(fill=BOTH, expand=False)

        art_body = Frame(self.article_tab, highlightbackground='gray', highlightthickness=1)

        scroll = Scrollbar(art_body, orient=VERTICAL)
        canvas = Canvas(art_body)
        scroll.pack(fill=Y, side=RIGHT, expand=False)
        scroll.config(command=canvas.yview)
        inner_frame = Frame(canvas)

        def check_valid_confirm():
            t = self.client.create_transaction()
            t = self.client.confirm_vote(t, art_name)
            return TransactionsValidator.valid_confirm(self.client, t)

        pend_arts = LabelFrame(inner_frame, text="Confirm your votes")
        rec_arts = LabelFrame(inner_frame, text="Recent articles")
        for art_name, article in self.client.articles.items():
            self.show_article(rec_arts, art_name, article)
            if check_valid_confirm():
                self.show_article(pend_arts, art_name, article)

        pend_arts.pack(fill=BOTH, expand=True)
        rec_arts.pack(fill=BOTH, expand=True)
        inner_frame.pack(fill=BOTH, expand=True)
        inner_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox('all')))

        canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        canvas.pack(fill=BOTH, expand=True)
        canvas.config(scrollregion=canvas.bbox('all'), yscrollcommand=scroll.set)
        art_body.pack(fill=BOTH, expand=True)


    def invite_init(self):
        pass

    def nodes_init(self):
        for child in self.nodes_tab.winfo_children():
            child.destroy()

        nodes_header = Frame(self.nodes_tab, highlightbackground='gray', highlightthickness=1)
        nodes_label = Label(nodes_header, text="Nodes list", anchor='w')
        nodes_label.pack(side=LEFT, fill=BOTH, expand=True, padx=20)

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
        self.client.update_state()
        res = self.client.resolve_conflicts()
        self.chain_init()
        self.profile_init()
        self.article_init()
        self.invite_init()
        if res:
            messagebox.showinfo("Chain update", "Chain successfully updated23!")
        else:
            messagebox.showwarning("Chain update", "Could not update chain.")

    def managekeys(self):
        popup = Tk()
        popup.title("Manage keys")
        popup.geometry('300x200')
        Label(popup, text="Manage RSA key pair\n").pack()
        my_key = b64encode(int.to_bytes(self.client.pubkey.n, KEY_LEN//8, 'big')).decode('utf-8')
        key_label = Label(popup, text=f"Public key:  {my_key[:6]}...{my_key[-4:]}", anchor='w')
        key_label.pack(fill=X, expand=False, padx=40)
        key_label.bind("<Button-1>", lambda e: messagebox.showinfo("Key info", f"{my_key}"))

        def import_keys():
            filename = filedialog.askopenfilename()
            if not filename:
                return
            try:
                self.client.load_keys(filename)
                with open(filename) as f, open("./rsa-id", "w") as g:
                    g.write(f.read())
                self.chain_init()
                self.profile_init()
                self.article_init()
                self.invite_init()
                self.nodes_init()
                popup.destroy()
                messagebox.showinfo("Key import", "Keys imported successfully.")
            except Exception as e:
                logging.error(e)
                messagebox.showerror("File error", f"Failed to open {filename}")

        def export_keys():
            filename = filedialog.asksaveasfilename()
            if not filename:
                return
            if not self.client.save_keys(filename):
                popup.destroy()
                messagebox.showinfo("Key export", f"Keys saved to {filename}")
            else:
                messagebox.showerror("Key export", f"Failed to save keys to {filename}")

        export_btn = Button(popup, text="Save key...", command=export_keys)
        export_btn.pack(side=LEFT, padx=20)
        import_btn = Button(popup, text="Import key...", command=import_keys)
        import_btn.pack(side=LEFT, padx=0)

    def new_node(self):
        popup = Tk()
        popup.title("New nodes")
        popup.geometry('300x400')
        Label(popup, text="Input node hosts here:").pack()
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

    def new_art(self):
        global DEPOSIT_MIN

        my_key = b64encode(int.to_bytes(self.client.pubkey.n, KEY_LEN//8, 'big')).decode('utf-8')
        if not self.client.balances.get(my_key) or self.client.balances[my_key] < DEPOSIT_MIN:
            messagebox.showerror("Error", "Can't create an article:\nYou are not permitted to post articles.")
            return

        popup = Tk()
        popup.title("New article")
        popup.geometry('400x280')

        def send_art():
            t = self.client.create_transaction()
            t = self.client.register_article(t, inputtxt.get(1.0, 'end-1c'), inputtxt2.get(1.0, 'end-1c'), float(deposit.get()))
            t = self.client.sign_transaction(t)
            popup.destroy()
            if TransactionsValidator.valid_transaction(self.client, t):
                self.client.push_transaction(t)
                self.chain_init()
                self.profile_init()
                self.article_init()
                messagebox.showinfo("Post article", "Article posted successfully.")
            else:
                logging.error("Invalid transaction encountered while posting article")
                messagebox.showerror("Error", "Invalid transaction! Check your params or consider updating chain.")
                return

        Label(popup, text="Article name:").pack()
        inputtxt = Text(popup, height=1, width=32)
        inputtxt.pack()

        Label(popup, text="Link / reference:").pack()
        inputtxt2 = Text(popup, height=1, width=32)
        inputtxt2.pack()

        deposit = Scale(popup, from_=DEPOSIT_MIN, to=self.client.balances[my_key], label="Deposit", orient=HORIZONTAL)
        deposit.pack()
        deposit.set(DEPOSIT_MIN)

        Button(popup, text="  Post  ", command=send_art).pack(side=RIGHT, padx=50)
        Button(popup, text="Cancel", command=lambda e=None: popup.destroy()).pack(side=LEFT, padx=50)

        popup.mainloop()

    def new_vote(self, name):
        popup = Tk()
        popup.title("Vote")
        popup.geometry('200x100')

        def send_vote(vote):
            t = self.client.create_transaction()
            t = self.client.vote_for_article(t, name, vote)
            t = self.client.sign_transaction(t)
            if not TransactionsValidator.valid_transaction(self.client, t):
                popup.destroy()
                logging.error("Invalid transaction encountered! Outdated chain?")
                messagebox.showerror("Error", "Invalid transaction encountered. Consider updating chain?")
                return
            self.client.push_transaction(t)
            self.chain_init()
            self.profile_init()
            self.article_init()
            popup.destroy()
            messagebox.showinfo("Submit vote", "Vote submited successfully.")

        Label(popup, text=f"Vote for:\n{name}").pack()
        Button(popup, text=" [ + ] ", command=self.func_handler(send_vote, 'pos')).pack(side=LEFT, expand=True, padx=20)
        Button(popup, text=" [ - ] ", command=self.func_handler(send_vote, 'neg')).pack(side=RIGHT, expand=True, padx=0)

        popup.mainloop()

    def confirm_vote(self, name):
        t = self.client.create_transaction()
        t = self.client.confirm_vote(t, name)
        t = self.client.sign_transaction(t)

        if not TransactionsValidator.valid_transaction(self.client, t):
            logging.error("Invalid transaction encountered! Outdated chain?")
            messagebox.showerror("Error", "Invalid transaction encountered. Consider updating chain?")
            return
        self.client.push_transaction(t)
        self.chain_init()
        self.profile_init()
        self.article_init()
        messagebox.showinfo("Confirm vote", "Vote confirmed successfully.")

    def show_article(self, root, art_name, article):
        article_frame = Frame(root, width=615, height=90, highlightbackground='gray', highlightthickness=1)

        name = Label(article_frame, text=f"   {art_name}\n\n {article['link'][:23]}", width=24)
        name.pack(side=LEFT, anchor='nw')
        name.bind("<Button-1>", self.func_handler(webbrowser.open, article['link']))

        tstamp = Label(article_frame, text=datetime.fromtimestamp(article['timestamp']).strftime('%d.%m.%Y %H:%M'), anchor='ne')
        tstamp.pack(side=RIGHT, anchor='ne')

        deposit = Label(article_frame, text=f"Deposit:  {article['deposit']}")
        deposit.pack(expand=True, ipadx=80)

        pos, neg = article['votes']['pos'], article['votes']['neg']
        time_passed = time() - article['timestamp']
        if time_passed <= VOTING_TIME:
            status = f"VOTING till {datetime.fromtimestamp(article['timestamp'] + VOTING_TIME).strftime('%d.%m.%Y %H:%M')}"
        elif time_passed <= VOTING_TIME + CONFIRM_TIME:
            status = f"CONFIRMING till {datetime.fromtimestamp(article['timestamp'] + VOTING_TIME + CONFIRM_TIME).strftime('%d.%m.%Y %H:%M')}"
        else:
            if pos > (neg + pos) * POS_THRESHOLD:
                status = "RATED TRUSTWORTHY"
            elif neg > (neg + pos) * NEG_THRESHOLD:
                status = "RATED FAKE"
            else:
                status = "MIXED RATING"

        def check_valid_vote():
            t = self.client.create_transaction()
            t['operation'] = 'vote'
            t['recipient'] = art_name
            t['vote_hash'] = 'aaa'
            return TransactionsValidator.valid_vote(self.client, t)

        def check_valid_confirm():
            t = self.client.create_transaction()
            t = self.client.confirm_vote(t, art_name)
            return TransactionsValidator.valid_confirm(self.client, t)

        Label(article_frame, text=status).pack(ipadx=80)
        if status.startswith("VOTING"):
            my_vote = self.client.nonces.get(art_name)
            if my_vote:
                if my_vote[0] == 'pos': my_vote = '+'
                else: my_vote = '-'
                Label(article_frame, text="You voted  [ " + my_vote + " ]").pack(ipadx=80)
            if check_valid_vote():
                vote_pos = Button(article_frame, text=f" [ + ] ", command=self.func_handler(self.new_vote, art_name))
                vote_neg = Button(article_frame, text=f" [ - ] ", command=self.func_handler(self.new_vote, art_name))
                vote_pos.pack(side=LEFT, fill=Y, padx=50)
                vote_neg.pack(side=LEFT, fill=Y, padx=0)
        if check_valid_confirm():
            Button(article_frame, text="Confirm vote", command=self.func_handler(self.confirm_vote, art_name)).pack()
        elif not check_valid_vote():
            votes = Label(article_frame, text=f"[+ {pos}]  [- {neg}]" + (f" ({round(pos / (pos + neg) * 100)} / {round(neg / (pos + neg) * 100)} %)" if pos or neg else ""))
            votes.pack(ipadx=80)

        article_frame.pack_propagate(0)
        article_frame.pack(fill=BOTH, expand=True)

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

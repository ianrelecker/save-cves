import sqlite3


key_value = "CVE-2024-11026"



conn = sqlite3.connect('processed_cves.db')
cursor = conn.cursor()


cursor.execute("DELETE FROM processed_cves WHERE cve_id = ?", (key_value,))
conn.commit()
cursor.execute("SELECT * FROM processed_cves WHERE cve_id = ?", (key_value,))
print(cursor.fetchall())

conn = sqlite3.connect('cve_reports.db')
cursor = conn.cursor()

cursor.execute("DELETE FROM processed WHERE cve_id = ?", (key_value,))
conn.commit()
cursor.execute("SELECT * FROM processed WHERE cve_id = ?", (key_value,))
print(cursor.fetchall())

'''
cursor.execute("DELETE FROM processed_cves WHERE cve_id = ?", (key_value,))
conn.commit()
cursor.execute("SELECT * FROM processed_cves WHERE cve_id = ?", (key_value,))
print(cursor.fetchall())

conn = sqlite3.connect('cve_reports.db')
cursor = conn.cursor()

cursor.execute("SELECT * FROM processed WHERE cve_id = ?", ("CVE-2023-38203",))
print(cursor.fetchall())
#cursor.execute("DELETE FROM processed WHERE cve_id = ?", (key_value,))

#conn.commit()
#cursor.execute("SELECT * FROM processed WHERE cve_id = ?", (key_value,))
#print(cursor.fetchall())

#cursor.execute("DELETE * FROM processed_cves WHERE ")
#rows = cursor.fetchall()

# Display the CVEs
#print("Processed CVEs:")
#for row in rows:
    #print(row[0])


#cursor.execute(f"PRAGMA table_info({'processed_cves'})")

# Clear all data in the table (without deleting the table itself)
#cursor.execute('DELETE FROM processed')
#cursor.execute('''#DROP TABLE processed''')
#cursor.execute('''CREATE TABLE processed (cve_id TEXT PRIMARY KEY)''')
#cursor.execute('''ALTER TABLE processed ADD COLUMN report TEXT''')
#conn.commit()
'''
conn = sqlite3.connect('kev_data.db')
cursor = conn.cursor()
#cursor.execute('ALTER TABLE processed_cves ADD COLUMN kev')
#list = ["CVE-2023-22952","CVE-2023-23376","CVE-2023-23397","CVE-2023-23529","CVE-2023-23752","CVE-2023-24489","CVE-2023-24880","CVE-2023-24955","CVE-2023-25280","CVE-2023-25717","CVE-2023-26083","CVE-2023-26359","CVE-2023-26360","CVE-2023-26369","CVE-2023-27350","CVE-2023-27524","CVE-2023-27532","CVE-2023-27992","CVE-2023-27997","CVE-2023-28204","CVE-2023-28205","CVE-2023-28206","CVE-2023-28229","CVE-2023-28252","CVE-2023-28432","CVE-2023-28434","CVE-2023-2868","CVE-2023-28771","CVE-2023-29298","CVE-2023-29300","CVE-2023-29336","CVE-2023-29357","CVE-2023-29360","CVE-2023-29492","CVE-2023-29552","CVE-2023-3079","CVE-2023-32046","CVE-2023-32049","CVE-2023-32315","CVE-2023-32373","CVE-2023-32409","CVE-2023-32434","CVE-2023-32435","CVE-2023-32439","CVE-2023-33009","CVE-2023-33010","CVE-2023-33063","CVE-2023-33106","CVE-2023-33107","CVE-2023-33246","CVE-2023-34048","CVE-2023-34362","CVE-2023-35078","CVE-2023-35081","CVE-2023-35082","CVE-2023-3519","CVE-2023-35311","CVE-2023-35674","CVE-2023-36025","CVE-2023-36033","CVE-2023-36036","CVE-2023-36563","CVE-2023-36584","CVE-2023-36761","CVE-2023-36802","CVE-2023-36844","CVE-2023-36845","CVE-2023-36846","CVE-2023-36847","CVE-2023-36851","CVE-2023-36874","CVE-2023-36884","CVE-2023-37450","CVE-2023-37580","CVE-2023-38035","CVE-2023-38180","CVE-2023-38203","CVE-2023-38205","CVE-2023-38606","CVE-2023-38831","CVE-2023-40044","CVE-2023-41061","CVE-2023-41064","CVE-2023-41179","CVE-2023-41265","CVE-2023-41266","CVE-2023-41763","CVE-2023-41990","CVE-2023-41991","CVE-2023-41992","CVE-2023-41993","CVE-2023-4211","CVE-2023-42793","CVE-2023-42824","CVE-2023-42916","CVE-2023-42917","CVE-2023-43208","CVE-2023-43770","CVE-2023-44487","CVE-2023-45249","CVE-2023-46604","CVE-2023-46747","CVE-2023-46748","CVE-2023-46805","CVE-2023-47246","CVE-2023-47565","CVE-2023-4762","CVE-2023-4863","CVE-2023-48788","CVE-2023-49103","CVE-2023-4911","CVE-2023-4966","CVE-2023-49897","CVE-2023-5217","CVE-2023-5631","CVE-2023-6345","CVE-2023-6448","CVE-2023-6548","CVE-2023-6549","CVE-2023-7024","CVE-2023-7028","CVE-2023-7101","CVE-2024-0519","CVE-2024-1086","CVE-2024-1709","CVE-2024-20353","CVE-2024-20359","CVE-2024-20399","CVE-2024-20481","CVE-2024-21338","CVE-2024-21351","CVE-2024-21410","CVE-2024-21412","CVE-2024-21762","CVE-2024-21887","CVE-2024-21893","CVE-2024-23113","CVE-2024-23222","CVE-2024-23225","CVE-2024-23296","CVE-2024-23692","CVE-2024-23897","CVE-2024-24919","CVE-2024-26169","CVE-2024-27198","CVE-2024-27348","CVE-2024-28986","CVE-2024-28987","CVE-2024-28995","CVE-2024-29745","CVE-2024-29748","CVE-2024-29824","CVE-2024-29988","CVE-2024-30040","CVE-2024-30051","CVE-2024-30088","CVE-2024-32113","CVE-2024-3272","CVE-2024-3273","CVE-2024-32896","CVE-2024-3400","CVE-2024-34102","CVE-2024-36401","CVE-2024-36971","CVE-2024-37085","CVE-2024-37383","CVE-2024-38014","CVE-2024-38080","CVE-2024-38094","CVE-2024-38106","CVE-2024-38107","CVE-2024-38112","CVE-2024-38178","CVE-2024-38189","CVE-2024-38193","CVE-2024-38213","CVE-2024-38217","CVE-2024-38226","CVE-2024-38856","CVE-2024-39717","CVE-2024-39891","CVE-2024-4040","CVE-2024-40711","CVE-2024-40766","CVE-2024-43047","CVE-2024-43093","CVE-2024-43451","CVE-2024-43461","CVE-2024-43572","CVE-2024-43573","CVE-2024-4358","CVE-2024-45519","CVE-2024-4577","CVE-2024-4610","CVE-2024-4671","CVE-2024-47575","CVE-2024-4761","CVE-2024-4879","CVE-2024-49039","CVE-2024-4947","CVE-2024-4978","CVE-2024-51567","CVE-2024-5217","CVE-2024-5274","CVE-2024-5910","CVE-2024-6670","CVE-2024-7262","CVE-2024-7593","CVE-2024-7965","CVE-2024-7971","CVE-2024-8190","CVE-2024-8956","CVE-2024-8957","CVE-2024-8963","CVE-2024-9379","CVE-2024-9380","CVE-2024-9463","CVE-2024-9465","CVE-2024-9537","CVE-2024-9680"]

for item in list:
    cursor.execute("""
               INSERT INTO kev_entries (cve_id, vendor, product, vulnerability_name, description, due_date)
               VALUES (?, ?, ?, ?, ?, ?)
           """, (item, "n", "n", "n", "n", "n"))
    conn.commit()

cursor.execute("SELECT cve_id FROM kev_entries")

#cursor.execute("DELETE FROM kev_entries")
#conn.commit()
# Commit the transaction
conn.commit()
#cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
listy = cursor.fetchall()
listy.reverse()
print(str(listy))

'''

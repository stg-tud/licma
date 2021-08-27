with open("../TestRuleVeryBig.java", "a") as file:
    i = 51
    while i <= 350:
        print(i)
        file.write("")
        file.write("/**")
        file.write(" * Test")
        file.write(" */")
        file.write("public class TestRule" + str(i) + " {")
        i = i + 1
        with open("template.txt") as tmp:
            for line in tmp.readlines():
                file.write(line)
            tmp.close()

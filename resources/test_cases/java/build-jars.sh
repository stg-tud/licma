#!/bin/bash

javac TestRule1.java TestRule2.java TestRule3.java TestRule4.java TestRule5.java TestRule6.java JavaCodeTest.java

jar cfm TestRule1.jar Manifest_TestRule1.txt TestRule1.class
jar cfm TestRule2.jar Manifest_TestRule2.txt TestRule2.class
jar cfm TestRule3.jar Manifest_TestRule3.txt TestRule3.class
jar cfm TestRule4.jar Manifest_TestRule4.txt TestRule4.class
jar cfm TestRule5.jar Manifest_TestRule5.txt TestRule5.class
jar cfm TestRule6.jar Manifest_TestRule6.txt TestRule6.class
jar cfm JavaCodeTest.jar Manifest_JavaCodeTest.txt TestRule1.class TestRule2.class TestRule3.class TestRule4.class TestRule5.class TestRule6.class JavaCodeTest.class

DEVELOPMENT ENVIRONMENT

JavaCard development with IBM's tools requires the following software.
The versions quoted here are the highest versions that worked for us.

Windows XP SP3 (Vista works, but why would you do that to yourself?)
JCOP 3.2.7 (nothing newer available)
Eclipse SDK 3.5.0 (requires preference settings)
Sun Java 1.5.0 Update 19 (private Eclipse JRE recommended, Java 6 does NOT work)

The most convenient option for activating JCOP 3.1.2 is using
"another activated installation". We keep a zipped workspace around.

Note that you only need this stack to do development. It is possible to
interface with smartcards on every OS, so you shouldn't need any of this
if you're just talking to a TEM.


MAKING JCOP BUILD UNDER ECLIPSE 3.2+

UPDATE: the codebase forces the changes needed, via the files in the .settings
folder. Look below only if the firmware does not build.

JCOP cannot CAPify classes above Java 1.4, and Eclipse 3.2+ default to Java 1.5.
1) Go to your JCOP project's preferences, then choose the Java Compiler tab.
2) Check 'Enable project specific settings'
3) Set 'Compiler compliance level' to 1.4
4) Uncheck 'Use default compliance settings'
5) Set 'Generated .class files compatibility' to 1.2
6) Set 'Source compatibility' to 1.3
7) OK

If your project is still not built, go to Project > Clean... and clean it.


RELEASING A NEW FIRMWARE VERSION

A new firmware version requires bumps in two places: the FIRMWARE_VER constant 
in TEMApplet.java, and the package version in the .cap file.

The FIRMWARE_VER constant has the major version in the first byte, and the minor
version in the second byte. Bump the minor version when adding / changing
features. Bump the major version for architectural redesigns.

To bump the version in the .cap file:
1) Open the Java perspective or the JCOP Development perspective
2) Browse to the edu.mit.csail.tc package under the src/ folder in the project
3) Right-click on the package, select Properties
4) Select 'JavaCard Settings' in the left list
5) Adjust the number under 'Package version'. Format: major.minor in decimal.


WORKING WITH THE SIMULATOR

Make sure to make the simulator listen to the fixed port (8050) instead
of a randomly selected port. Otherwise the TEM driver will not be able
to connect to the simulator.


WORKING WITH REAL CARDS

Normal applet deletion will not work on a deactivated TEM, because of
object references in static fields. Because of this, pretty much every
operation will issue error 6985 (conditions of use not satisfied).

The applet can be removed by deleting its containing package. To do this:
1) hook up a JCOP shell to the card
2) issue a "card-info" command to see the applet's AID
3) find the shorter AID (should be 1229198310)
4) issue "delete -r the_AID" (should be "delete -r 1229198310")

In order to run Java code against actual cards, you need to copy the DLLs
in <<eclipse root>>\plugins\com.ibm.bluez.jcop.eclipse_3.1.2\os\win32\x86
to <<windows root>>\system32. You can try dropping them in
<<eclipse root>>\jre\bin (or wherever your JRE is) but your mileage may
vary (it doesn't always work for us).

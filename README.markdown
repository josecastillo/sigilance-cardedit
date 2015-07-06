# SIGILANCE CardEdit

This is a small utility for editing the data on NFC-enabled OpenPGP smart cards.

When you launch the app, you are prompted to tap a NFC-enabled smart card on the back of your device. When you do, you will see a listing of all the data on the card. After you tap the card, you may remove it and set it aside; the app works in transactions, and you will be prompted when you need to tap the card again. 

There is an edit button next to the data objects that are editable, but it is disabled by default. To enable edit mode, tap the Action menu, and then tap "Enable Edit Mode". You will have to enter the Admin PIN, which by default is 12345678. After you enter the PIN, you will be prompted to tap the card again. The edit buttons will become enabled if the PIN was valid; if not, you will have to tap "Enable Edit Mode" again and try a different PIN.

After you edit a data object, you will be prompted to tap the card again. This transaction will re-validate the PIN, edit the data object, and re-fetch all data objects.

Once a card has been tapped, you can change both the User PIN and the Admin PIN using the "Change User PIN" and "Change Admin PIN" options in the action menu.

This code derives in part from GPLv3 code from the OpenKeychain project, and is released under the same licensing terms. 

Joey Castillo  
www.sigilance.com

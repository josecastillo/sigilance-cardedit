/*
 * Copyright (C) 2015 Joey Castillo <joey@joeycastillo.com>
 *
 * This file derives in part from GPLv3 code from the OpenKeychain project:
 * Copyright (C) 2015 Dominik Schürmann <dominik@dominikschuermann.de>
 * Copyright (C) 2015 Vincent Breitmoser <v.breitmoser@mugenguild.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.sigilance.CardEdit;

import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.support.v4.app.Fragment;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.InputFilter;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.TimeZone;


public class MainActivity extends AppCompatActivity {

    private abstract class PendingOperation {
        protected int mSlot;

        public int getSlot() {
            return mSlot;
        }
    }

    private class PendingPutDataOperation extends PendingOperation {
        private byte[] mData;

        public PendingPutDataOperation(int slot, byte[] data) {
            mSlot = slot;
            mData = data;
        }

        public byte[] getData() {
            return mData;
        }
    }

    private class PendingVerifyPinOperation extends PendingOperation {
        private String mPin;

        public PendingVerifyPinOperation(int mode, String pin) {
            mSlot = mode;
            mPin = pin;
        }

        public String getPin() {
            return mPin;
        }

        public void setPin(String pin) {
            mPin = pin;
        }
    }

    private class PendingChangePinOperation extends PendingOperation {
        private String mOldPin;
        private String mNewPin;

        public PendingChangePinOperation(int slot, String oldPin, String newPin) {
            mSlot = slot;
            mOldPin = oldPin;
            mNewPin = newPin;
        }

        public String getOldPin() {
            return mOldPin;
        }

        public String getNewPin() {
            return mNewPin;
        }
    }

    private IsoDep isoDep;
    private NfcAdapter mNfcAdapter;

    private boolean mPw3Verified = false;

    // NOTE: The formats for on-card data vary depending on the DO.
    // These are defined to be binary
    private byte[] mCurrentAid = null;
    private byte[] mPrivateDo1 = null;
    private byte[] mPrivateDo2 = null;
    private byte[] mPrivateDo3 = null;
    private byte[] mPrivateDo4 = null;
    private byte[] mLoginData = null;
    private byte[] mPwStatusBytes = null;

    // These are defined to be ISO 8859-1
    private String mCardholderName = null;

    // These are defined to be ASCII
    private String mUrl = null;
    private String mCardholderLanguage = null;
    private String mCardholderSex = null;

    // These are binary, but we're going to convert them to strings for display
    private String mSigKeyFingerprint = null;
    private String mEncKeyFingerprint = null;
    private String mAuthKeyFingerprint = null;

    // These are UNIX epoch timestamps. Unsigned ints, which we need to represent as Java longs
    private long mSigKeyTimestamp;
    private long mEncKeyTimestamp;
    private long mAuthKeyTimestamp;

    // And this is a three-byte array that we'll represent as an integer.
    private Integer mSignatureCount = null;

    private ArrayList<PendingOperation> mPendingOperations = new ArrayList<PendingOperation>();

    // Static stuff
    private static final String BLANK_FINGERPRINT = "0000000000000000000000000000000000000000";

    // Status words
    static final byte[] SW_ACCEPTED = {(byte) 0x90, 0x00};

    // DO slots for reading and writing
    static final int DO_PRIVATE_1 = 0x0101;
    static final int DO_PRIVATE_2 = 0x0102;
    static final int DO_PRIVATE_3 = 0x0103;
    static final int DO_PRIVATE_4 = 0x0104;
    static final int DO_LOGIN_DATA = 0x005E;
    static final int DO_URL = 0x5F50;
    static final int DO_PW1_STATUS_BYTE = 0x00C4;

    // DO slots for reading only
    static final int DO_AID = 0x004F;
    static final int DO_CARDHOLDER_DATA = 0x0065;
    static final int DO_APPLICATION_DATA = 0x006E;
    static final int DO_SECURITY_TEMPLATE = 0x007A;
    static final int DO_PW_STATUS_BYTES = 0x00C4;

    // DO slots for writing only
    static final int DO_NAME = 0x005B;
    static final int DO_LANGUAGE = 0x5F2D;
    static final int DO_SEX = 0x5F35;

    // Tags for compound objects
    static final int TAG_FINGERPRINTS = 0xC5;
    static final int TAG_TIMESTAMPS = 0xCD;
    static final int TAG_NAME = 0x005B;
    static final int TAG_LANGUAGE = 0x5F2D;
    static final int TAG_SEX = 0x5F35;
    static final int TAG_SIG_COUNT = 0x93;

    // PIN slots
    static final int PIN_PW1 = 0x81;
    static final int PIN_PW3 = 0x83;

    /**
     * Called when the system is about to start resuming a previous activity,
     * disables NFC Foreground Dispatch
     */
    public void onPause() {
        super.onPause();
        disableNfcForegroundDispatch();
    }

    public void onStop() {
        super.onStop();
        dissociateFromCard();
    }

    /**
     * Called when the activity will start interacting with the user,
     * enables NFC Foreground Dispatch
     */
    public void onResume() {
        super.onResume();
        enableNfcForegroundDispatch();
    }

    /**
     * Receive new NFC Intents to this activity only by enabling foreground dispatch.
     * This can only be done in onResume!
     */
    public void enableNfcForegroundDispatch() {
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (mNfcAdapter == null) {
            return;
        }
        Intent nfcI = new Intent(this, getClass())
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent nfcPendingIntent = PendingIntent.getActivity(this, 0, nfcI, PendingIntent.FLAG_CANCEL_CURRENT);
        IntentFilter[] writeTagFilters = new IntentFilter[]{
                new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED)
        };

        try {
            mNfcAdapter.enableForegroundDispatch(this, nfcPendingIntent, writeTagFilters, null);
        } catch (IllegalStateException e) {
            Toast.makeText(this, "NfcForegroundDispatch Error!", Toast.LENGTH_LONG).show();
        }
    }

    /**
     * Disable foreground dispatch in onPause!
     */
    public void disableNfcForegroundDispatch() {
        if (mNfcAdapter == null) {
            return;
        }
        mNfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.app_name);
        setContentView(R.layout.activity_main);
        if (savedInstanceState == null) {
            getSupportFragmentManager().beginTransaction()
                    .add(R.id.container, new PlaceholderFragment())
                    .commit();
        }
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu)
    {
        if(mCurrentAid == null) {
            menu.findItem(R.id.action_change_pw1).setVisible(false);
            menu.findItem(R.id.action_change_pw3).setVisible(false);
            menu.findItem(R.id.action_different_card).setVisible(false);
        } else {
            menu.findItem(R.id.action_change_pw1).setVisible(true);
            menu.findItem(R.id.action_change_pw3).setVisible(true);
            menu.findItem(R.id.action_different_card).setVisible(true);
        }

        if (mPw3Verified) {
            menu.findItem(R.id.action_verify_pw3).setVisible(false);
        } else {
            menu.findItem(R.id.action_verify_pw3).setVisible(true);
        }

        return true;
    }

    void removePendingOperation(Class type, int mode) {
        for (PendingOperation op : mPendingOperations)
            if (op.getClass().equals(type) && op.getSlot() == mode)
                mPendingOperations.remove(op);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        switch (id) {
            case R.id.action_verify_pw3:
                removePendingOperation(PendingVerifyPinOperation.class, PIN_PW3);
                promptForVerifyPin(PIN_PW3);
                return true;
            case R.id.action_change_pw1:
                removePendingOperation(PendingChangePinOperation.class, PIN_PW1);
                promptForChangePin(PIN_PW1);
                return true;
            case R.id.action_change_pw3:
                removePendingOperation(PendingChangePinOperation.class, PIN_PW3);
                promptForChangePin(PIN_PW3);
                return true;
            case R.id.action_different_card:
                dissociateFromCard();
                return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private void dissociateFromCard() {
        // Note: We don't have to null out everything else, because the UI won't show again until
        // after a successful GET DATA of all the card data.
        for (PendingOperation op : mPendingOperations)
            mPendingOperations.remove(op);
        mPw3Verified = false;
        mCurrentAid = null;
        findTextViewById(R.id.id_action_reqiured_warning).setText(R.string.warning_tap_card_to_view);
        hideUi();
    }

    private void promptForChangePin(final int mode) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        if (mode == 0x83)
            builder.setTitle(R.string.action_change_pw3);
        else
            builder.setTitle(R.string.action_change_pw1);

        final String typeString = mode == 0x83 ? "Admin" : "User";
        String defaultString = mode == 0x83 ? "12345678" : "123456";
        builder.setMessage(String.format("REMINDER: The default %s PIN is %s", typeString, defaultString));
        final EditText oldPinInput = new EditText(this);
        oldPinInput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        oldPinInput.setHint(String.format("Old %s PIN", mode == 0x83 ? "Admin" : "User"));
        final EditText newPinInput = new EditText(this);
        newPinInput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        newPinInput.setHint(String.format("New %s PIN", mode == 0x83 ? "Admin" : "User"));
        final EditText confirmPinInput = new EditText(this);
        confirmPinInput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        confirmPinInput.setHint("Repeat New PIN");
        LinearLayout fields = new LinearLayout(this);
        fields.setOrientation(LinearLayout.VERTICAL);
        fields.addView(oldPinInput);
        fields.addView(newPinInput);
        fields.addView(confirmPinInput);
        builder.setView(fields);

        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                // Placeholder; we will override this
            }
        });
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });

        final AlertDialog dialog = builder.create();
        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                if(oldPinInput.getText().toString().length() == 0 || newPinInput.getText().toString().length() == 0) {
                    Toast.makeText(MainActivity.this, "Enter a PIN!", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (!(confirmPinInput.getText().toString().equals(newPinInput.getText().toString()))) {
                    newPinInput.setText("");
                    confirmPinInput.setText("");
                    Toast.makeText(MainActivity.this, "PINs did not match.", Toast.LENGTH_SHORT).show();
                    return;
                }
                int minPinLength = (mode == 0x83) ? 8 : 6;
                if (oldPinInput.getText().toString().length() < minPinLength || newPinInput.getText().toString().length() < minPinLength) {
                    newPinInput.setText("");
                    confirmPinInput.setText("");
                    Toast.makeText(MainActivity.this, String.format("%s PIN must be at least %d digits.", typeString, minPinLength), Toast.LENGTH_SHORT).show();
                    return;
                }
                // Once we have valid PINs, add the pending operation.
                mPendingOperations.add(
                        new PendingChangePinOperation(mode,
                                oldPinInput.getText().toString(),
                                newPinInput.getText().toString()));
                // And prompt the user to change the PIN.
                hideUi();
                findTextViewById(R.id.id_action_reqiured_warning).setText(R.string.warning_tap_card_to_change);
                dialog.dismiss();
            }
        });
    }

    private void promptForVerifyPin(final int mode) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.action_enable_edit_mode);
        builder.setMessage("Enter the Admin PIN to edit data on the card.\nREMINDER: The default Admin PIN is 12345678");
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        builder.setView(input);

        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                if(input.getText().toString().length() == 0) {
                    Toast.makeText(MainActivity.this, "Enter a PIN!", Toast.LENGTH_SHORT).show();
                    return;
                }
                int minPinLength = (mode == 0x83) ? 8 : 6;
                if (input.getText().toString().length() < minPinLength) {
                    input.setText("");
                    Toast.makeText(MainActivity.this, String.format("PIN is at least %d digits.", minPinLength), Toast.LENGTH_SHORT).show();
                    return;
                }
                mPendingOperations.add(new PendingVerifyPinOperation(mode, input.getText().toString()));
                hideUi();
                findTextViewById(R.id.id_action_reqiured_warning).setText(R.string.warning_tap_card_to_verify);
            }
        });
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });

        builder.create().show();
    }

    private void promptForTextDo(final int slot) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);

        final EditText input = new EditText(this);
        final EditText input2 = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT);
        input2.setInputType(InputType.TYPE_CLASS_TEXT);
        LinearLayout fields = new LinearLayout(this);
        fields.setOrientation(LinearLayout.VERTICAL);
        fields.addView(input);

        switch (slot) {
            case DO_NAME:
                builder.setTitle(R.string.lbl_cardholder_name);
                input.setHint(R.string.hint_surname);
                input2.setHint(R.string.hint_given_name);
                input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS);
                input2.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS);

                String[] names = mCardholderName.split("<<");
                if(names.length > 1) {
                    input.setText(names[0].replace('<', ' '));
                    input2.setText(names[1].replace('<', ' '));
                }
                fields.addView(input2);
                break;
            case DO_LANGUAGE:
                builder.setTitle(R.string.lbl_language_prefs);
                builder.setMessage("Use a two-letter ISO 639-1 language code: en for English, es for Spanish, etc.");
                input.setFilters( new InputFilter[] { new InputFilter.LengthFilter(2) } );
                input.setText(mCardholderLanguage);
                break;
            case DO_LOGIN_DATA:
                builder.setTitle(R.string.lbl_login_data);
                builder.setMessage("This is arbitrary text; you can use this field to store a username, email address or network logon.");
                input.setFilters( new InputFilter[] { new InputFilter.LengthFilter(254) } );
                input.setText(new String(mLoginData));
                break;
            case DO_URL:
                builder.setTitle(R.string.lbl_url);
                input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
                input.setFilters( new InputFilter[] { new InputFilter.LengthFilter(254) } );
                input.setText(mUrl);
                break;
        }

        builder.setView(fields);

        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                byte[] data;
                String text = input.getText().toString();

                switch (slot) {
                    case DO_NAME:
                        String surname = text.trim().replace(' ', '<');
                        String givenNames = input2.getText().toString().trim().replace(' ', '<');
                        data = (surname + "<<" + givenNames).getBytes(Charset.forName("ISO-8859-1"));
                        if (data.length > 39) {
                            Toast.makeText(MainActivity.this, "Name is too long!", Toast.LENGTH_LONG).show();
                            return;
                        }
                        break;
                    case DO_LANGUAGE:
                        if (text.length() == 2)
                            data = text.toLowerCase().getBytes();
                        else
                            data = new byte[0];
                        break;
                    case DO_URL:
                    case DO_LOGIN_DATA:
                        data = text.getBytes();
                        break;
                    default:
                        data = new byte[0];
                }

                mPendingOperations.add(new PendingPutDataOperation(slot, data));
                hideUi();
                findTextViewById(R.id.id_action_reqiured_warning).setText(R.string.warning_tap_card_to_save);
            }
        });
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });

        builder.create().show();
    }

    private void promptForSexDo() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.lbl_sex);

        String[] options = new String[]{
                getString(R.string.lbl_male),
                getString(R.string.lbl_female),
                getString(R.string.lbl_gender_unspecifed)};
        int currentIndex = -1;
        switch (mCardholderSex) {
            case "1":
                currentIndex = 0;
                break;
            case "2":
                currentIndex = 1;
                break;
            case "9":
                currentIndex = 2;
                break;
        }
        builder.setSingleChoiceItems(options, currentIndex, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int item) {
            }
        });

        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                ListView lw = ((AlertDialog)dialog).getListView();
                switch(lw.getCheckedItemPosition())
                {
                    case 0:
                        mPendingOperations.add(new PendingPutDataOperation(DO_SEX, new byte[]{0x31}));
                        break;
                    case 1:
                        mPendingOperations.add(new PendingPutDataOperation(DO_SEX, new byte[]{0x32}));
                        break;
                    case 2:
                        mPendingOperations.add(new PendingPutDataOperation(DO_SEX, new byte[]{0x39}));
                        break;
                    default:
                        return;
                }
                hideUi();
                findTextViewById(R.id.id_action_reqiured_warning).setText(R.string.warning_tap_card_to_save);
            }
        });
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });

        builder.create().show();
    }

    private void promptForPinBehaviorDo() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.lbl_signature_pin);

        String[] options = new String[]{
                getString(R.string.lbl_pin_forced),
                getString(R.string.lbl_pin_not_forced)};
        builder.setSingleChoiceItems(options, mPwStatusBytes[0], new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int index) {

            }
        });

        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                ListView lw = ((AlertDialog)dialog).getListView();
                byte[] data;
                if(lw.getCheckedItemPosition() == 0)
                    data = new byte[]{0};
                else
                    data = new byte[]{1};
                mPendingOperations.add(new PendingPutDataOperation(DO_PW1_STATUS_BYTE, data));
                hideUi();
                findTextViewById(R.id.id_action_reqiured_warning).setText(R.string.warning_tap_card_to_save);
            }
        });
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });

        builder.create().show();
    }

    /**
     * A placeholder fragment containing a simple view.
     */
    public static class PlaceholderFragment extends Fragment {

        public PlaceholderFragment() {
        }

        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container,
                                 Bundle savedInstanceState) {
            View rootView = inflater.inflate(R.layout.fragment_main, container, false);
            return rootView;
        }
    }

    @Override
    public void onNewIntent(Intent intent) {
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(intent.getAction())) {
            try {
                handleNdefDiscoveredIntent(intent);
            } catch (IOException e) {
                handleNfcError(e);
            }
        }
    }

    private void hideUi() {
        findViewById(R.id.id_action_reqiured_warning).setVisibility(View.VISIBLE);
        findViewById(R.id.id_version_container).setVisibility(View.GONE);
        findViewById(R.id.id_manufacturer_container).setVisibility(View.GONE);
        findViewById(R.id.id_serialno_container).setVisibility(View.GONE);
        findViewById(R.id.id_name_container).setVisibility(View.GONE);
        findViewById(R.id.id_lang_container).setVisibility(View.GONE);
        findViewById(R.id.id_sex_container).setVisibility(View.GONE);
        findViewById(R.id.id_url_container).setVisibility(View.GONE);
        findViewById(R.id.id_logindata_container).setVisibility(View.GONE);
        findViewById(R.id.id_forcesig_container).setVisibility(View.GONE);
        findViewById(R.id.id_sigcount_container).setVisibility(View.GONE);
        findViewById(R.id.id_sigkey_container).setVisibility(View.GONE);
        findViewById(R.id.id_enckey_container).setVisibility(View.GONE);
        findViewById(R.id.id_authkey_container).setVisibility(View.GONE);
    }

    private void showUi() {
        findViewById(R.id.id_action_reqiured_warning).setVisibility(View.GONE);
        findViewById(R.id.id_version_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_manufacturer_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_serialno_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_name_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_lang_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_sex_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_url_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_logindata_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_forcesig_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_sigcount_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_sigkey_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_enckey_container).setVisibility(View.VISIBLE);
        findViewById(R.id.id_authkey_container).setVisibility(View.VISIBLE);
    }

    private void disableEditControls() {
        findViewById(R.id.btn_edit_name).setEnabled(false);
        findViewById(R.id.btn_edit_lang).setEnabled(false);
        findViewById(R.id.btn_edit_sex).setEnabled(false);
        findViewById(R.id.btn_edit_url).setEnabled(false);
        findViewById(R.id.btn_edit_logindata).setEnabled(false);
        findViewById(R.id.btn_edit_forcesig).setEnabled(false);
    }

    private void enableEditControls() {
        findViewById(R.id.btn_edit_name).setEnabled(true);
        findViewById(R.id.btn_edit_lang).setEnabled(true);
        findViewById(R.id.btn_edit_sex).setEnabled(true);
        findViewById(R.id.btn_edit_url).setEnabled(true);
        findViewById(R.id.btn_edit_logindata).setEnabled(true);
        findViewById(R.id.btn_edit_forcesig).setEnabled(true);

        findButtonById(R.id.btn_edit_name).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                promptForTextDo(DO_NAME);
            }
        });
        findButtonById(R.id.btn_edit_lang).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                promptForTextDo(DO_LANGUAGE);
            }
        });
        findButtonById(R.id.btn_edit_sex).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                promptForSexDo();
            }
        });
        findButtonById(R.id.btn_edit_url).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                promptForTextDo(DO_URL);
            }
        });
        findButtonById(R.id.btn_edit_logindata).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                promptForTextDo(DO_LOGIN_DATA);
            }
        });
        findButtonById(R.id.btn_edit_forcesig).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                promptForPinBehaviorDo();
            }
        });

    }

    private void populateSimpleField(int id, String text) {
        TextView textView = findTextViewById(id);
        if (text.equals("") || text.equals(BLANK_FINGERPRINT)) {
            textView.setText(R.string.lbl_empty);
            textView.setTypeface(null, Typeface.ITALIC);
        } else {
            textView.setText(text);
            textView.setTypeface(null, Typeface.NORMAL);
        }
    }

    private static String formatEpochDate(long timestamp) {
        if (timestamp == 0)
            return " ";

        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("GMT"));
        return df.format(new Date(timestamp * 1000));
    }

    private String getManufacturer() {
        int manufacturerId = (mCurrentAid[8] << 8) | mCurrentAid[9];
        switch (manufacturerId) {
            case 0x0005:
                return "ZeitControl";
            case 0x0006:
                return "Yubico";
            case 0x7615:
                return "SIGILANCE";
            case 0xF517:
                return "FSIJ";
            case 0x0000:
            case 0xffff:
                return "test card";
            default:
                if ((manufacturerId & 0xff00) == 0xff00)
                    return "unmanaged S/N range";
                else
                    return "unknown";
        }
    }

    private String getVersion() {
        String aidString = hexString(mCurrentAid);
        // Spec states that this version string is BCD, so 0x10 is 10, not 16.
        int majorVersion = Integer.parseInt(aidString.substring(12, 14));
        int minorVersion = Integer.parseInt(aidString.substring(14, 16));
        return String.format("%d.%d", majorVersion, minorVersion);
    }

    private String getSerialNumber() {
        String aidString = hexString(mCurrentAid);
        return aidString.substring(20, 28);
    }

    private TextView findTextViewById(int id) {
        return (TextView) findViewById(id);
    }

    private ImageButton findButtonById(int id) {
        return (ImageButton) findViewById(id);
    }

    private void refreshUi() {
        if (mCurrentAid == null) {
            hideUi();
            return;
        }

        showUi();

        if (mPw3Verified) {
            enableEditControls();
        } else {
            disableEditControls();
        }

        populateSimpleField(R.id.id_version_content, getVersion());
        populateSimpleField(R.id.id_manufacturer_content, getManufacturer());
        populateSimpleField(R.id.id_serialno_content, getSerialNumber());

        populateSimpleField(R.id.id_name_content, mCardholderName);
        populateSimpleField(R.id.id_lang_content, mCardholderLanguage);

        populateSimpleField(R.id.id_url_content, mUrl);
        populateSimpleField(R.id.id_logindata_content, new String(mLoginData));

        populateSimpleField(R.id.id_sigcount_content, String.format("%d", mSignatureCount));

        switch (mCardholderSex) {
            case "1":
                findTextViewById(R.id.id_sex_content).setText(R.string.lbl_male);
                break;
            case "2":
                findTextViewById(R.id.id_sex_content).setText(R.string.lbl_female);
                break;
            default:
                findTextViewById(R.id.id_sex_content).setText(R.string.lbl_gender_unspecifed);
                break;
        }

        if(mPwStatusBytes[0] == 1)
            findTextViewById(R.id.id_forcesig_content).setText(R.string.lbl_pin_not_forced);
        else
            findTextViewById(R.id.id_forcesig_content).setText(R.string.lbl_pin_forced);

        populateSimpleField(R.id.id_sigkey_fingerprint_content, mSigKeyFingerprint);
        populateSimpleField(R.id.id_sigkey_timestamp_content, formatEpochDate(mSigKeyTimestamp));

        populateSimpleField(R.id.id_enckey_fingerprint_content, mEncKeyFingerprint);
        populateSimpleField(R.id.id_enckey_timestamp_content, formatEpochDate(mEncKeyTimestamp));

        populateSimpleField(R.id.id_authkey_fingerprint_content, mAuthKeyFingerprint);
        populateSimpleField(R.id.id_authkey_timestamp_content, formatEpochDate(mAuthKeyTimestamp));
    }

    public byte[] nfcCommunicate(byte[] apdu) throws IOException {
        return isoDep.transceive(apdu);
    }

    /**
     * Gets a data object from the card.
     * Supported for all data objects < 255 bytes in length. Only the cardholder certificate
     * (0x7F21) can exceed this length.
     *
     * @param dataObject The data object to get.
     */
    public byte[] nfcGetData(int dataObject) throws IOException {
        byte p1 = (byte) ((dataObject & 0xFF00) >> 8);
        byte p2 = (byte) (dataObject & 0x00FF);

        byte[] getDataApdu = {0x00, (byte) 0xCA, p1, p2, 0x00};
        byte[] response = nfcCommunicate(getDataApdu);

        byte[] sw = Arrays.copyOfRange(response, response.length - 2, response.length);

        if (!Arrays.equals(sw, SW_ACCEPTED)) {
            throw new IOException("GET DATA failed!");
        }

        return Arrays.copyOf(response, response.length - 2);
    }

    /**
     * Stores a data object on the card. Automatically validates the proper PIN for the operation.
     * Supported for all data objects < 255 bytes in length. Only the cardholder certificate
     * (0x7F21) can exceed this length.
     *
     * @param dataObject The data object to be stored.
     * @param data       The data to store in the object
     */
    public void nfcPutData(int dataObject, byte[] data) throws IOException {
        byte p1 = (byte) ((dataObject & 0xFF00) >> 8);
        byte p2 = (byte) (dataObject & 0x00FF);

        byte[] putDataHeader = {0x00, (byte) 0xDA, p1, p2, (byte) data.length};
        byte[] putDataApdu = new byte[putDataHeader.length + data.length];
        System.arraycopy(putDataHeader, 0, putDataApdu, 0, putDataHeader.length);
        System.arraycopy(data, 0, putDataApdu, putDataHeader.length, data.length);

        byte[] response = nfcCommunicate(putDataApdu);

        if (!Arrays.equals(response, SW_ACCEPTED)) {
            throw new IOException("PUT DATA failed!");
        }
    }

    /**
     * Modifies the user's PW1 or PW3. Before sending, the new PIN will be validated for
     * conformance to the card's requirements for key length.
     *
     * @param slot   For PW1, this is 0x81. For PW3 (Admin PIN), mode is 0x83.
     * @param oldPin The old PW1 or PW3.
     * @param newPin The new PW1 or PW3.
     */
    public void nfcModifyPIN(int slot, String oldPin, String newPin) throws IOException {
        byte[] pins = (oldPin + newPin).getBytes();
        byte[] changePinHeader = {0x00, 0x24, 0x00, (byte) slot, (byte) pins.length};
        byte[] changePinApdu = new byte[changePinHeader.length + pins.length];
        System.arraycopy(changePinHeader, 0, changePinApdu, 0, changePinHeader.length);
        System.arraycopy(pins, 0, changePinApdu, changePinHeader.length, pins.length);

        byte[] response = nfcCommunicate(changePinApdu); // change PIN
        if (!Arrays.equals(response, SW_ACCEPTED)) {
            showUi();
            throw new IOException("CHANGE PIN failed!");
        }
    }

    /** Verifies the user's PW1 or PW3 with the appropriate mode.
     *
     * @param mode For PW1, this is 0x81 for signing, 0x82 for everything else.
     *             For PW3 (Admin PIN), mode is 0x83.
     */
    public void nfcVerifyPIN(int mode, String pinString) throws IOException {
        if (pinString != null || mode == 0x83) {
            if (pinString == null || pinString.length() < 6)
                throw new IOException("Invalid PIN!");
            byte[] pin = pinString.getBytes();
            byte[] verifyPinHeader = {0x00, 0x20, 0x00, (byte)mode, (byte)pin.length};
            byte[] verifyPinApdu = new byte[verifyPinHeader.length + pin.length];
            System.arraycopy(verifyPinHeader, 0, verifyPinApdu, 0, verifyPinHeader.length);
            System.arraycopy(pin, 0, verifyPinApdu, verifyPinHeader.length, pin.length);

            byte[] response = nfcCommunicate(verifyPinApdu);
            if (!Arrays.equals(response, SW_ACCEPTED)) {
                showUi();
                throw new IOException("Incorrect PIN. Do not attempt again with the same PIN, or you risk locking the card!");
            }

            if (mode == 0x83) {
                mPw3Verified = true;
            }
        }
    }

    protected void handleNdefDiscoveredIntent(Intent intent) throws IOException {
        Tag detectedTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        isoDep = IsoDep.get(detectedTag);
        isoDep.setTimeout(100000); // timeout is set to 100 seconds to avoid cancellation during calculation
        isoDep.connect();

        byte[] opening = {0x00, (byte) 0xA4, 0x04, 0x00, 0x06, (byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00};
        byte[] response = nfcCommunicate(opening);
        if (!Arrays.equals(response, SW_ACCEPTED)) {
            throw new IOException("Initialization failed!");
        }

        byte[] aid = nfcGetData(DO_AID);

        // If user is touching card for the first time, cache the AID.
        if (mCurrentAid == null) {
            mCurrentAid = aid;
        }

        // Confirm that they're still tapping the same card.
        if (!Arrays.equals(aid, mCurrentAid)) {
            throw new IOException("Serial numbers did not match; did you tap a different card?");
        }

        // With safety checks out of the way, perform pending operations.
        if (mPendingOperations.size() > 0) {
            String newAdminPIN = null;

            for (PendingOperation operation : mPendingOperations) {
                if (operation instanceof PendingVerifyPinOperation) {
                    PendingVerifyPinOperation op = (PendingVerifyPinOperation) operation;
                    nfcVerifyPIN(op.getSlot(), op.getPin());
                    // NOTE: We do not remove the verify operation, because if the user wants to
                    // edit another DO, we'll need to transmit it again.
                } else if (operation instanceof PendingPutDataOperation) {
                    PendingPutDataOperation op = (PendingPutDataOperation) operation;
                    nfcPutData(op.getSlot(), op.getData());
                    mPendingOperations.remove(op);
                } else if (operation instanceof PendingChangePinOperation) {
                    PendingChangePinOperation op = (PendingChangePinOperation) operation;
                    nfcModifyPIN(op.getSlot(), op.getOldPin(), op.getNewPin());
                    if (op.getSlot() == 0x83)
                        newAdminPIN = op.getNewPin();
                    mPendingOperations.remove(op);
                    Toast.makeText(this, "PIN was changed.", Toast.LENGTH_LONG).show();
                }
            }

            // If we changed the Admin PIN, we need the VERIFY command to reflect the new PIN.
            if (newAdminPIN != null)
                for (PendingOperation operation : mPendingOperations)
                    if (operation instanceof PendingVerifyPinOperation) {
                        PendingVerifyPinOperation op = (PendingVerifyPinOperation) operation;
                        if (op.getSlot() == 0x83)
                            op.setPin(newAdminPIN);
                    }
        }

        // Finally, get all the data and show the UI.
        byte[] cardholderData = nfcGetData(DO_CARDHOLDER_DATA);
        Iso7816TLV chTlv = Iso7816TLV.readSingle(cardholderData, true);
        mCardholderName = new String(Iso7816TLV.findRecursive(chTlv, TAG_NAME).mV);
        mCardholderSex = new String(Iso7816TLV.findRecursive(chTlv, TAG_SEX).mV);
        mCardholderLanguage = new String(Iso7816TLV.findRecursive(chTlv, TAG_LANGUAGE).mV);

        mUrl = new String(nfcGetData(DO_URL));
        mLoginData = nfcGetData(DO_LOGIN_DATA);

        byte[] appData = nfcGetData(DO_APPLICATION_DATA);
        Iso7816TLV appTlv = Iso7816TLV.readSingle(appData, true);
        byte[] fingerprints = Iso7816TLV.findRecursive(appTlv, TAG_FINGERPRINTS).mV;
        mSigKeyFingerprint = hexString(Arrays.copyOfRange(fingerprints, 0, 20));
        mEncKeyFingerprint = hexString(Arrays.copyOfRange(fingerprints, 20, 40));
        mAuthKeyFingerprint = hexString(Arrays.copyOfRange(fingerprints, 40, 60));
        byte[] timestamps = Iso7816TLV.findRecursive(appTlv, TAG_TIMESTAMPS).mV;
        mSigKeyTimestamp = unsignedFromByteArray(Arrays.copyOfRange(timestamps, 0, 4));
        mEncKeyTimestamp = unsignedFromByteArray(Arrays.copyOfRange(timestamps, 4, 8));
        mAuthKeyTimestamp = unsignedFromByteArray(Arrays.copyOfRange(timestamps, 8, 12));

        mPwStatusBytes = nfcGetData(DO_PW_STATUS_BYTES);

        byte[] secData = nfcGetData(DO_SECURITY_TEMPLATE);
        Iso7816TLV secTlv = Iso7816TLV.readSingle(secData, true);
        byte[] sigCount = {0, 0, 0, 0};
        byte[] sigCountFromCard = Iso7816TLV.findRecursive(secTlv, TAG_SIG_COUNT).mV;
        System.arraycopy(sigCountFromCard, 0, sigCount, 1, 3);
        mSignatureCount = ByteBuffer.wrap(sigCount).getInt();

        refreshUi();
    }

    public void handleNfcError(IOException e) {
        Toast.makeText(this, "Exception: " + e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
    }

    final protected static char[] HEX_CHARACTERS = "0123456789ABCDEF".toCharArray();

    public static String hexString(byte[] bytes) {
        char[] retVal = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            retVal[i * 2] = HEX_CHARACTERS[v >>> 4];
            retVal[i * 2 + 1] = HEX_CHARACTERS[v & 0x0F];
        }
        return new String(retVal);
    }

    long unsignedFromByteArray(byte[] b) {
        long l = 0;
        l |= b[0] & 0xFF;
        l <<= 8;
        l |= b[1] & 0xFF;
        l <<= 8;
        l |= b[2] & 0xFF;
        l <<= 8;
        l |= b[3] & 0xFF;
        return l;
    }

}
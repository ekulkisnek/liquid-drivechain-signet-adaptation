// Copyright (c) 2026 The LayerTwo Labs developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_LWKWALLETDIALOG_H
#define BITCOIN_QT_LWKWALLETDIALOG_H

#include <QDialog>
#include <QString>

class ClientModel;
class QLabel;
class QLineEdit;
class QPushButton;
class QTextEdit;
class QTableWidget;

QT_BEGIN_NAMESPACE
class QWidget;
QT_END_NAMESPACE

/** Dialog for Liquid Wallet Kit (LWK) basic wallet functionality */
class LwkWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit LwkWalletDialog(ClientModel* clientModel, QWidget* parent = nullptr);
    ~LwkWalletDialog() override;

private Q_SLOTS:
    void onRefreshClicked();
    void onSendClicked();
    void onCopyClicked();

private:
    ClientModel* m_client_model;

    // UI Widgets
    QLabel* m_balance_label;
    QLineEdit* m_address_edit;
    QPushButton* m_copy_button;
    QPushButton* m_refresh_button;

    QLineEdit* m_send_dest_edit;
    QLineEdit* m_send_amount_edit;
    QPushButton* m_send_button;
    QLabel* m_send_status_label;

    QTableWidget* m_history_table;

    void updateWalletInfo();
};

#endif // BITCOIN_QT_LWKWALLETDIALOG_H

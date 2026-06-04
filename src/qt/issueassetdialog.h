// Copyright (c) 2026 The LayerTwo Labs developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ISSUEASSETDIALOG_H
#define BITCOIN_QT_ISSUEASSETDIALOG_H

#include <QDialog>

class ClientModel;
class QLineEdit;
class QPushButton;
class QTextEdit;
class QLabel;

class IssueAssetDialog : public QDialog
{
    Q_OBJECT

public:
    explicit IssueAssetDialog(ClientModel* clientModel, QWidget* parent = nullptr);
    ~IssueAssetDialog();

private Q_SLOTS:
    void onIssueClicked();
    void onCloseClicked();

private:
    ClientModel* m_client_model;
    QLineEdit* m_asset_amount_edit;
    QLineEdit* m_token_amount_edit;
    QLineEdit* m_asset_name_edit; // optional metadata for UI
    QPushButton* m_issue_button;
    QPushButton* m_close_button;
    QTextEdit* m_result_text;
    QLabel* m_status_label;
};

#endif // BITCOIN_QT_ISSUEASSETDIALOG_H

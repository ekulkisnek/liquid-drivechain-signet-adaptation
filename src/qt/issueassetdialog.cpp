// Copyright (c) 2026 The LayerTwo Labs developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/issueassetdialog.h>

#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <interfaces/node.h>
#include <univalue.h>

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

#include <string>

IssueAssetDialog::IssueAssetDialog(ClientModel* clientModel, QWidget* parent)
    : QDialog(parent),
      m_client_model(clientModel)
{
    setWindowTitle(tr("Issue New Asset (Elements)"));
    setModal(true);
    setMinimumWidth(500);

    auto* layout = new QVBoxLayout(this);

    m_status_label = new QLabel(tr("Issue a new asset on Elements. This uses the 'issueasset' RPC. Amounts are in BTC units (8 decimals)."), this);
    m_status_label->setWordWrap(true);
    layout->addWidget(m_status_label);

    auto* form = new QFormLayout();

    m_asset_amount_edit = new QLineEdit("10", this);
    m_asset_amount_edit->setPlaceholderText("e.g. 1000.0");
    form->addRow(tr("Asset amount (L-BTC units):"), m_asset_amount_edit);

    m_token_amount_edit = new QLineEdit("1", this);
    m_token_amount_edit->setPlaceholderText("e.g. 0 or 1");
    form->addRow(tr("Reissuance token amount:"), m_token_amount_edit);

    m_asset_name_edit = new QLineEdit("", this);
    m_asset_name_edit->setPlaceholderText("(optional) name for your reference");
    form->addRow(tr("Asset name (UI only):"), m_asset_name_edit);

    layout->addLayout(form);

    m_result_text = new QTextEdit(this);
    m_result_text->setReadOnly(true);
    m_result_text->setPlaceholderText(tr("Result will appear here (asset ID, txid, etc.)"));
    layout->addWidget(m_result_text);

    auto* buttonBox = new QDialogButtonBox(this);
    m_issue_button = buttonBox->addButton(tr("&Issue Asset"), QDialogButtonBox::AcceptRole);
    m_close_button = buttonBox->addButton(QDialogButtonBox::Close);
    layout->addWidget(buttonBox);

    connect(m_issue_button, &QPushButton::clicked, this, &IssueAssetDialog::onIssueClicked);
    connect(m_close_button, &QPushButton::clicked, this, &IssueAssetDialog::onCloseClicked);

    if (!m_client_model) {
        m_status_label->setText(tr("No client model available. Cannot issue assets."));
        m_issue_button->setEnabled(false);
    }
}

IssueAssetDialog::~IssueAssetDialog() = default;

void IssueAssetDialog::onIssueClicked()
{
    if (!m_client_model) return;

    m_result_text->clear();
    m_status_label->setText(tr("Issuing..."));

    double asset_amt = m_asset_amount_edit->text().toDouble();
    double token_amt = m_token_amount_edit->text().toDouble();

    if (asset_amt <= 0) {
        QMessageBox::warning(this, tr("Error"), tr("Asset amount must be positive."));
        return;
    }

    try {
        // Build params for issueasset RPC: asset_amount, token_amount [, blind]
        UniValue params(UniValue::VARR);
        params.push_back(m_asset_amount_edit->text().toStdString());
        params.push_back(m_token_amount_edit->text().toStdString());
        // blind=true by default for confidential

        UniValue result = m_client_model->node().executeRpc("issueasset", params, /* auth? */ "");

        QString res_str = QString::fromStdString(result.write(2 /* pretty */));
        m_result_text->setPlainText(res_str);

        // Try to extract asset id for user
        if (result.isObject() && result.exists("asset")) {
            std::string asset_hex = result["asset"].get_str();
            m_status_label->setText(tr("Success! Asset ID: %1 (copy from result)").arg(QString::fromStdString(asset_hex)));
        } else {
            m_status_label->setText(tr("Asset issued successfully. See result below."));
        }
    } catch (const std::exception& e) {
        m_status_label->setText(tr("Error issuing asset."));
        m_result_text->setPlainText(QString("Error: %1\n\nTry using elements-cli issueasset %2 %3 or the RPC console.")
            .arg(QString::fromStdString(e.what()))
            .arg(m_asset_amount_edit->text())
            .arg(m_token_amount_edit->text()));
        QMessageBox::critical(this, tr("Issue Asset Error"), QString::fromStdString(e.what()));
    }
}

void IssueAssetDialog::onCloseClicked()
{
    accept();
}

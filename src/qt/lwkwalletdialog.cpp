// Copyright (c) 2026 The LayerTwo Labs developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/lwkwalletdialog.h>

#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonParseError>

#include <stdexcept>
#include <string>

static const QString POLICY_ASSET = "0000000000000000000000000000000000000000000000000000000000000000";

static QJsonDocument RunLwkWalletCommand(const QStringList& arguments)
{
    QProcess process;
    QString scriptPath = "/Volumes/T705/code/liquid-signet-sidechain/drivechain-liquid-sidechain/scripts/lwk_wallet.py";
    
    // Set Python environment if needed to be unbuffered
    process.setProcessEnvironment(QProcessEnvironment::systemEnvironment());
    
    process.start("python3", QStringList() << scriptPath << arguments);
    if (!process.waitForFinished(15000)) {
        throw std::runtime_error("LWK wallet command timed out.");
    }
    
    if (process.exitCode() != 0) {
        QString err = process.readAllStandardError();
        if (err.isEmpty()) err = process.readAllStandardOutput();
        throw std::runtime_error(err.toStdString());
    }
    
    QByteArray output = process.readAllStandardOutput();
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(output, &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        throw std::runtime_error("Failed to parse JSON response: " + parseError.errorString().toStdString());
    }
    return doc;
}

LwkWalletDialog::LwkWalletDialog(ClientModel* clientModel, QWidget* parent)
    : QDialog(parent),
      m_client_model(clientModel)
{
    setWindowTitle(tr("LWK Wallet"));
    setModal(true);
    setMinimumSize(700, 600);

    // Apply Premium Dark QSS stylesheet
    setStyleSheet(
        "QDialog {"
        "    background-color: #121214;"
        "    color: #e2e8f0;"
        "    font-family: 'Inter', -apple-system, sans-serif;"
        "}"
        "QGroupBox {"
        "    border: 1px solid #2d3748;"
        "    border-radius: 8px;"
        "    margin-top: 12px;"
        "    padding-top: 16px;"
        "    font-weight: bold;"
        "    color: #e2e8f0;"
        "    background-color: #1a202c;"
        "}"
        "QGroupBox::title {"
        "    subcontrol-origin: margin;"
        "    subcontrol-position: top left;"
        "    padding: 0 8px;"
        "    color: #3182ce;"
        "}"
        "QLabel {"
        "    color: #a0aec0;"
        "    font-size: 13px;"
        "}"
        "QLineEdit {"
        "    background-color: #2d3748;"
        "    border: 1px solid #4a5568;"
        "    border-radius: 6px;"
        "    padding: 8px;"
        "    color: #ffffff;"
        "    font-size: 13px;"
        "}"
        "QLineEdit:focus {"
        "    border: 1px solid #3182ce;"
        "    background-color: #1a202c;"
        "}"
        "QPushButton {"
        "    background-color: #3182ce;"
        "    color: #ffffff;"
        "    border: none;"
        "    border-radius: 6px;"
        "    padding: 8px 16px;"
        "    font-weight: bold;"
        "    font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #4299e1;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #2b6cb0;"
        "}"
        "QPushButton:disabled {"
        "    background-color: #4a5568;"
        "    color: #a0aec0;"
        "}"
        "QTableWidget {"
        "    background-color: #1a202c;"
        "    border: 1px solid #2d3748;"
        "    gridline-color: #2d3748;"
        "    border-radius: 6px;"
        "    color: #e2e8f0;"
        "}"
        "QHeaderView::section {"
        "    background-color: #2d3748;"
        "    color: #a0aec0;"
        "    padding: 6px;"
        "    border: 1px solid #1a202c;"
        "    font-weight: bold;"
        "}"
    );

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    // Header info (Balance, Refresh)
    auto* headerLayout = new QHBoxLayout();
    m_balance_label = new QLabel(tr("L-BTC Balance: Loading..."), this);
    m_balance_label->setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;");
    headerLayout->addWidget(m_balance_label);
    
    headerLayout->addStretch();
    
    m_refresh_button = new QPushButton(tr("Sync / Refresh"), this);
    m_refresh_button->setStyleSheet("background-color: #2b6cb0;");
    headerLayout->addWidget(m_refresh_button);
    mainLayout->addLayout(headerLayout);

    // Group 1: Receive (Generate / Copy address)
    auto* receiveGroup = new QGroupBox(tr("Receive L-BTC (Confidential)"), this);
    auto* receiveLayout = new QVBoxLayout(receiveGroup);
    auto* receiveForm = new QFormLayout();
    
    m_address_edit = new QLineEdit(this);
    m_address_edit->setReadOnly(true);
    m_address_edit->setStyleSheet("font-family: monospace; font-size: 12px;");
    
    m_copy_button = new QPushButton(tr("Copy"), this);
    m_copy_button->setFixedWidth(100);
    
    receiveForm->addRow(tr("Address:"), m_address_edit);
    receiveLayout->addLayout(receiveForm);
    receiveLayout->addWidget(m_copy_button, 0, Qt::AlignRight);
    
    mainLayout->addWidget(receiveGroup);

    // Group 2: Send (Destination, Amount)
    auto* sendGroup = new QGroupBox(tr("Send L-BTC (Confidential)"), this);
    auto* sendLayout = new QVBoxLayout(sendGroup);
    auto* sendForm = new QFormLayout();

    m_send_dest_edit = new QLineEdit(this);
    m_send_dest_edit->setPlaceholderText(tr("el1... confidential address"));
    sendForm->addRow(tr("Pay To:"), m_send_dest_edit);

    m_send_amount_edit = new QLineEdit(this);
    m_send_amount_edit->setPlaceholderText(tr("Amount in satoshis (e.g. 5000000)"));
    sendForm->addRow(tr("Amount (sats):"), m_send_amount_edit);

    sendLayout->addLayout(sendForm);

    auto* sendControlLayout = new QHBoxLayout();
    m_send_status_label = new QLabel("", this);
    m_send_status_label->setStyleSheet("color: #e53e3e;");
    sendControlLayout->addWidget(m_send_status_label);
    
    m_send_button = new QPushButton(tr("Send L-BTC"), this);
    m_send_button->setFixedWidth(150);
    sendControlLayout->addWidget(m_send_button);
    sendLayout->addLayout(sendControlLayout);

    mainLayout->addWidget(sendGroup);

    // Group 3: History (Transaction table)
    auto* historyGroup = new QGroupBox(tr("Transaction History"), this);
    auto* historyLayout = new QVBoxLayout(historyGroup);
    
    m_history_table = new QTableWidget(this);
    m_history_table->setColumnCount(4);
    m_history_table->setHorizontalHeaderLabels(QStringList() << tr("Time") << tr("Type") << tr("Net Balance (sats)") << tr("Transaction ID"));
    m_history_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_history_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_history_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_history_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    historyLayout->addWidget(m_history_table);

    mainLayout->addWidget(historyGroup);

    // Close button at bottom
    auto* footerLayout = new QHBoxLayout();
    footerLayout->addStretch();
    auto* closeButton = new QPushButton(tr("Close"), this);
    closeButton->setStyleSheet("background-color: #4a5568;");
    footerLayout->addWidget(closeButton);
    mainLayout->addLayout(footerLayout);

    // Connect signals
    connect(m_refresh_button, &QPushButton::clicked, this, &LwkWalletDialog::onRefreshClicked);
    connect(m_copy_button, &QPushButton::clicked, this, &LwkWalletDialog::onCopyClicked);
    connect(m_send_button, &QPushButton::clicked, this, &LwkWalletDialog::onSendClicked);
    connect(closeButton, &QPushButton::clicked, this, &LwkWalletDialog::accept);

    // Initialize/Run init command, then refresh info
    try {
        RunLwkWalletCommand(QStringList() << "init");
        updateWalletInfo();
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Init Error"), tr("Failed to initialize LWK wallet:\n%1").arg(e.what()));
    }
}

LwkWalletDialog::~LwkWalletDialog() = default;

void LwkWalletDialog::updateWalletInfo()
{
    try {
        m_balance_label->setText(tr("L-BTC Balance: Syncing..."));
        
        // 1. Sync & Get Balance
        QJsonDocument balanceDoc = RunLwkWalletCommand(QStringList() << "balance");
        QJsonObject balanceObj = balanceDoc.object();
        QJsonObject balances = balanceObj["balances"].toObject();
        
        qint64 lbtcBalance = 0;
        if (balances.contains(POLICY_ASSET)) {
            lbtcBalance = balances[POLICY_ASSET].toVariant().toLongLong();
        }
        
        double lbtcBtc = static_cast<double>(lbtcBalance) / 100000000.0;
        m_balance_label->setText(tr("L-BTC Balance: %1 sats (%2 L-BTC)")
            .arg(lbtcBalance)
            .arg(QString::number(lbtcBtc, 'f', 8)));

        // 2. Get Address
        QJsonDocument addressDoc = RunLwkWalletCommand(QStringList() << "address");
        QJsonObject addressObj = addressDoc.object();
        m_address_edit->setText(addressObj["address"].toString());

        // 3. Get History
        QJsonDocument historyDoc = RunLwkWalletCommand(QStringList() << "transactions");
        QJsonArray historyArr = historyDoc.array();
        
        m_history_table->setRowCount(0);
        for (int i = 0; i < historyArr.size(); ++i) {
            QJsonObject tx = historyArr[i].toObject();
            m_history_table->insertRow(i);
            
            // Format time
            QString timeStr = tr("Unconfirmed");
            if (!tx["timestamp"].isNull()) {
                qint64 secs = tx["timestamp"].toVariant().toLongLong();
                timeStr = QDateTime::fromSecsSinceEpoch(secs).toString("yyyy-MM-dd HH:mm:ss");
            }
            
            // Format balance
            QJsonObject balanceMap = tx["balance"].toObject();
            qint64 txBal = 0;
            if (balanceMap.contains(POLICY_ASSET)) {
                txBal = balanceMap[POLICY_ASSET].toVariant().toLongLong();
            }
            QString balStr = (txBal >= 0 ? "+" : "") + QString::number(txBal);

            m_history_table->setItem(i, 0, new QTableWidgetItem(timeStr));
            m_history_table->setItem(i, 1, new QTableWidgetItem(tx["type"].toString()));
            m_history_table->setItem(i, 2, new QTableWidgetItem(balStr));
            
            auto* txidItem = new QTableWidgetItem(tx["txid"].toString());
            txidItem->setFont(QFont("monospace", 10));
            m_history_table->setItem(i, 3, txidItem);
        }
        
        m_send_status_label->setText("");
    } catch (const std::exception& e) {
        m_balance_label->setText(tr("L-BTC Balance: Error updating"));
        m_send_status_label->setText(tr("Update error: %1").arg(e.what()));
    }
}

void LwkWalletDialog::onRefreshClicked()
{
    m_refresh_button->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    
    updateWalletInfo();
    
    QApplication::restoreOverrideCursor();
    m_refresh_button->setEnabled(true);
}

void LwkWalletDialog::onCopyClicked()
{
    QApplication::clipboard()->setText(m_address_edit->text());
}

void LwkWalletDialog::onSendClicked()
{
    QString dest = m_send_dest_edit->text().trimmed();
    QString amountStr = m_send_amount_edit->text().trimmed();
    
    if (dest.isEmpty()) {
        m_send_status_label->setText(tr("Please specify a destination address."));
        return;
    }
    
    bool ok;
    qint64 amount = amountStr.toLongLong(&ok);
    if (!ok || amount <= 0) {
        m_send_status_label->setText(tr("Amount must be a positive integer (sats)."));
        return;
    }
    
    m_send_button->setEnabled(false);
    m_send_status_label->setText(tr("Building and signing transaction..."));
    QApplication::setOverrideCursor(Qt::WaitCursor);
    
    try {
        QJsonDocument sendDoc = RunLwkWalletCommand(QStringList() << "send" << dest << QString::number(amount));
        QJsonObject sendObj = sendDoc.object();
        
        if (sendObj.contains("success") && sendObj["success"].toBool()) {
            QString txid = sendObj["txid"].toString();
            QMessageBox::information(this, tr("Transaction Sent"),
                tr("Transaction successfully broadcasted!\n\nTxid: %1").arg(txid));
            m_send_dest_edit->clear();
            m_send_amount_edit->clear();
            updateWalletInfo();
        } else {
            QString err = sendObj["error"].toString();
            m_send_status_label->setText(tr("Error: %1").arg(err));
        }
    } catch (const std::exception& e) {
        m_send_status_label->setText(tr("Send failed: %1").arg(e.what()));
    }
    
    QApplication::restoreOverrideCursor();
    m_send_button->setEnabled(true);
}

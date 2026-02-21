/**
 * Gmail add-on that sends a compact version of the current message
 * to the phishing detector backend.
 *
 * Required setup:
 * - BACKEND_BASE_URL constant set to your ngrok HTTPS URL.
 * - Advanced Google service "Gmail API" enabled.
 */

const BACKEND_BASE_URL = '';
const DETECT_ENDPOINT_PATH = '/api/v1/detect';

const MAX_COMPACT_BODY_CHARS = 12000;
const MAX_SECTION_CHARS = 4000;
const MAX_LINKS = 30;
const MAX_ATTACHMENTS = 20;

function onHomepage() {
  return buildInfoCard_();
}

function onGmailMessageOpen(e) {
  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Email Phishing Detector')
        .setSubtitle('Analyze this email with local backend via ngrok')
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            'Click Analyze to send a compact payload (text + links + attachment names).'
          )
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Analyze Current Email')
            .setOnClickAction(CardService.newAction().setFunctionName('analyzeCurrentMessage'))
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        )
    );

  return card.build();
}

function analyzeCurrentMessage(e) {
  try {
    const backendBaseUrl = getBackendBaseUrl_();
    const message = fetchCurrentMessage_(e);
    const compactMessage = toCompactApiMessage_(message);

    const payload = {
      source: 'gmail_addon',
      message: compactMessage,
    };

    const payloadJson = JSON.stringify(payload);
    console.log('detect_payload=' + payloadJson);

    const response = UrlFetchApp.fetch(backendBaseUrl + DETECT_ENDPOINT_PATH, {
      method: 'post',
      contentType: 'application/json',
      muteHttpExceptions: true,
      payload: payloadJson,
      headers: {
        'x-request-id': Utilities.getUuid(),
      },
    });

    const statusCode = response.getResponseCode();
    const bodyText = response.getContentText();
    const parsed = parseJsonSafe_(bodyText);

    if (statusCode >= 400) {
      return buildErrorCard_(statusCode, parsed, bodyText, payloadJson);
    }

    return buildResultCard_(statusCode, parsed);
  } catch (err) {
    return buildExceptionCard_(err);
  }
}

function fetchCurrentMessage_(e) {
  if (!e || !e.gmail || !e.gmail.messageId || !e.gmail.accessToken) {
    throw new Error('Missing Gmail context. Open an email and run from message view.');
  }

  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return Gmail.Users.Messages.get('me', e.gmail.messageId, { format: 'full' });
}

function getBackendBaseUrl_() {
  if (!BACKEND_BASE_URL || !String(BACKEND_BASE_URL).trim()) {
    throw new Error(
      'BACKEND_BASE_URL is not set in Code.gs. Example: https://abc123.ngrok-free.app'
    );
  }

  const normalized = String(BACKEND_BASE_URL).trim().replace(/\/$/, '');
  if (!/^https:\/\//.test(normalized)) {
    throw new Error('BACKEND_BASE_URL must use HTTPS (required by Gmail add-ons).');
  }

  return normalized;
}

function parseJsonSafe_(text) {
  try {
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

function toCompactApiMessage_(message) {
  const acc = {
    plainChunks: [],
    htmlChunks: [],
    links: [],
    attachments: [],
  };

  collectContent_(message && message.payload, acc);

  const plainText = joinAndTrim_(acc.plainChunks, MAX_SECTION_CHARS);
  const htmlText = joinAndTrim_(acc.htmlChunks.map(stripHtmlTags_), MAX_SECTION_CHARS);
  const links = uniqueList_(acc.links).slice(0, MAX_LINKS);
  const attachments = uniqueList_(acc.attachments).slice(0, MAX_ATTACHMENTS);

  const compactBody = buildCompactBody_(message && message.snippet, plainText, htmlText, links, attachments);

  return {
    id: toNullableString_(message && message.id),
    threadId: toNullableString_(message && message.threadId),
    snippet: toNullableString_(message && message.snippet),
    payload: {
      partId: '',
      mimeType: 'text/plain',
      filename: '',
      headers: filterHeaders_(message && message.payload && message.payload.headers),
      body: {
        data: encodeBase64Url_(compactBody),
        size: compactBody.length,
        attachmentId: null,
      },
      parts: null,
    },
    raw: null,
  };
}

function collectContent_(part, acc) {
  if (!part || typeof part !== 'object') {
    return;
  }

  const mimeType = String(part.mimeType || '').toLowerCase();

  if (part.filename && String(part.filename).trim()) {
    acc.attachments.push(String(part.filename).trim());
  }

  const decoded = decodeBodyData_(part.body && part.body.data);
  if (decoded) {
    if (mimeType.indexOf('text/html') >= 0) {
      acc.htmlChunks.push(decoded);
      Array.prototype.push.apply(acc.links, extractUrls_(decoded));
    } else if (mimeType.indexOf('text/plain') >= 0 || mimeType === '') {
      acc.plainChunks.push(decoded);
      Array.prototype.push.apply(acc.links, extractUrls_(decoded));
    }
  }

  if (Array.isArray(part.parts)) {
    part.parts.forEach(function (nested) {
      collectContent_(nested, acc);
    });
  }
}

function filterHeaders_(headers) {
  if (!Array.isArray(headers)) {
    return [];
  }

  const allowed = {
    from: true,
    'reply-to': true,
    subject: true,
    to: true,
  };

  return headers
    .filter(function (h) {
      const name = h && h.name ? String(h.name).toLowerCase() : '';
      return !!allowed[name];
    })
    .map(function (h) {
      return {
        name: toNullableString_(h.name),
        value: toNullableString_(h.value),
      };
    });
}

function buildCompactBody_(snippet, plainText, htmlText, links, attachments) {
  const sections = [];

  if (snippet) {
    sections.push('Snippet:\n' + truncate_(String(snippet), 500));
  }

  if (plainText) {
    sections.push('Plain text:\n' + plainText);
  }

  if (htmlText) {
    sections.push('HTML-derived text:\n' + htmlText);
  }

  if (links.length > 0) {
    sections.push('Extracted links:\n' + links.join('\n'));
  }

  if (attachments.length > 0) {
    sections.push('Attachment names:\n' + attachments.join('\n'));
  }

  const combined = sections.join('\n\n');
  return truncate_(combined, MAX_COMPACT_BODY_CHARS);
}

function decodeBodyData_(data) {
  if (!data) {
    return '';
  }

  try {
    const bytes = Utilities.base64DecodeWebSafe(String(data));
    return Utilities.newBlob(bytes).getDataAsString('UTF-8');
  } catch (_) {
    return '';
  }
}

function encodeBase64Url_(text) {
  const encoded = Utilities.base64EncodeWebSafe(String(text), Utilities.Charset.UTF_8);
  return encoded.replace(/=+$/g, '');
}

function stripHtmlTags_(html) {
  if (!html) {
    return '';
  }

  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractUrls_(text) {
  if (!text) {
    return [];
  }

  const matches = String(text).match(/https?:\/\/[^\s<>"')]+/gi);
  return matches ? matches : [];
}

function joinAndTrim_(chunks, maxChars) {
  const clean = chunks
    .map(function (chunk) {
      return String(chunk || '').trim();
    })
    .filter(function (chunk) {
      return chunk.length > 0;
    });

  return truncate_(clean.join('\n\n'), maxChars);
}

function uniqueList_(values) {
  const seen = {};
  const out = [];

  values.forEach(function (value) {
    const key = String(value || '').trim();
    if (!key) {
      return;
    }
    if (!seen[key]) {
      seen[key] = true;
      out.push(key);
    }
  });

  return out;
}

function truncate_(text, maxChars) {
  const value = String(text || '');
  if (value.length <= maxChars) {
    return value;
  }
  return value.slice(0, maxChars) + ' ...[truncated]';
}

function toNullableString_(value) {
  if (value === undefined || value === null) {
    return null;
  }
  return String(value);
}

function buildResultCard_(statusCode, responseJson) {
  const result = responseJson && responseJson.result ? responseJson.result : null;
  const error = responseJson && responseJson.error ? responseJson.error : null;

  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader()
      .setTitle('Phishing Analysis Result')
      .setSubtitle('HTTP ' + String(statusCode))
  );

  const section = CardService.newCardSection();

  if (error) {
    section.addWidget(
      CardService.newTextParagraph().setText(
        '<b>' + sanitize_(error.code || 'UNKNOWN_ERROR') + '</b><br/>' + sanitize_(error.message || '')
      )
    );
    card.addSection(section);
    return card.build();
  }

  if (!result) {
    section.addWidget(CardService.newTextParagraph().setText('No result payload returned.'));
    card.addSection(section);
    return card.build();
  }

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Verdict')
      .setContent(sanitize_(String(result.verdict || 'unknown')))
      .setBottomLabel('Risk: ' + String(result.risk_score || 0) + ' | Confidence: ' + String(result.confidence || 0))
  );

  section.addWidget(CardService.newTextParagraph().setText(sanitize_(String(result.summary || ''))));

  const triggers = Array.isArray(result.triggers) ? result.triggers : [];
  if (triggers.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText('No triggers returned.'));
  } else {
    const lines = triggers.slice(0, 5).map(function (t, idx) {
      return (
        String(idx + 1) +
        '. [' + sanitize_(String(t.kind || 'other')) + '] ' +
        sanitize_(String(t.value || '')) +
        ' - ' +
        sanitize_(String(t.reason || ''))
      );
    });
    section.addWidget(
      CardService.newTextParagraph().setText('<b>Top Triggers</b><br/>' + lines.join('<br/>'))
    );
  }

  card.addSection(section);
  return card.build();
}

function buildErrorCard_(statusCode, responseJson, rawBody, payloadJson) {
  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader()
      .setTitle('Backend Error')
      .setSubtitle('HTTP ' + String(statusCode))
  );

  const section = CardService.newCardSection();

  if (responseJson && responseJson.error) {
    section.addWidget(
      CardService.newTextParagraph().setText(
        '<b>' + sanitize_(String(responseJson.error.code || 'UNKNOWN_ERROR')) + '</b><br/>' +
          sanitize_(String(responseJson.error.message || ''))
      )
    );

    const detailsText = formatValidationDetails_(responseJson);
    if (detailsText) {
      section.addWidget(
        CardService.newTextParagraph().setText('<b>Details</b><br/>' + sanitize_(detailsText))
      );
    }
  } else {
    section.addWidget(
      CardService.newTextParagraph().setText(
        'Non-JSON error response:<br/><font color="#777777">' + sanitize_(String(rawBody || '')) + '</font>'
      )
    );
  }

  if (payloadJson) {
    const preview = payloadJson.length > 1500 ? payloadJson.slice(0, 1500) + '...' : payloadJson;
    section.addWidget(
      CardService.newTextParagraph().setText(
        '<b>Payload Preview</b><br/><font color="#777777">' + sanitize_(preview) + '</font>'
      )
    );
  }

  card.addSection(section);
  return card.build();
}

function buildExceptionCard_(err) {
  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Addon Error')
  );

  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(sanitize_(err && err.message ? err.message : String(err)))
    )
  );

  return card.build();
}

function buildInfoCard_() {
  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Email Phishing Detector')
  );

  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newTextParagraph().setText(
          'Open any email and use the add-on panel to analyze phishing risk.'
        )
      )
      .addWidget(
        CardService.newTextParagraph().setText(
          'Make sure BACKEND_BASE_URL in Code.gs is set to your ngrok HTTPS URL.'
        )
      )
      .addWidget(
        CardService.newTextParagraph().setText(
          'Addon sends compact payload: text + links + attachment names (not full MIME).'
        )
      )
  );

  return card.build();
}

function sanitize_(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatValidationDetails_(responseJson) {
  if (!responseJson || !responseJson.error || !Array.isArray(responseJson.error.details)) {
    return '';
  }

  const all = [];
  responseJson.error.details.forEach(function (entry) {
    if (entry && Array.isArray(entry.errors)) {
      entry.errors.forEach(function (err) {
        const loc = Array.isArray(err.loc) ? err.loc.join('.') : '';
        const msg = err && err.msg ? String(err.msg) : '';
        if (loc || msg) {
          all.push((loc ? loc + ': ' : '') + msg);
        }
      });
    }
  });

  return all.slice(0, 6).join(' | ');
}
